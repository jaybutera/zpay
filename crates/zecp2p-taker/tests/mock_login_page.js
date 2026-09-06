// A stand-in for Venmo's sign-in page, enough to run the login steps against.
//
// The unit tests in `auto::login` assert over the *text* of the generated
// JavaScript: that it clears React's value tracker, that it matches buttons by
// their label rather than by `button[type='submit']`. That catches a step that
// stops doing the right thing, and it cannot catch a step whose JavaScript does
// not run at all, or whose selector matches nothing on a page shaped like the
// real one. Those are the two failures that actually cost a live run, and they
// are what this file exists to catch.
//
// It is a DOM shim rather than jsdom on purpose. Pulling jsdom in would make
// `cargo test` depend on an npm install reaching the network, and the surface
// the login steps touch is small enough to implement honestly: querySelector
// over a selector list, `_valueTracker`, input/change events, `innerText`,
// `disabled`, and `location.href`.
//
// The markup below mirrors Venmo's real form as `auto::login`'s selectors
// describe it: a username input with no test id, a password input identified
// only by `type='password'`, and a sign-in button carrying no id, no test id and
// no aria-label, so it can only be found by its text.

'use strict';

// ---------------------------------------------------------------------------
// The DOM shim
// ---------------------------------------------------------------------------

class Element {
  constructor(tag, attrs = {}, text = '') {
    this.tagName = tag.toUpperCase();
    this.attrs = attrs;
    this.innerText = text;
    this.value = attrs.value || '';
    this.disabled = !!attrs.disabled;
    this.events = [];
    // React's value tracker: the thing a plain `el.value =` fails to update,
    // which is why a fill that does not clear it is silently discarded.
    //
    // `cleared` is what distinguishes the two fills. React's real tracker is
    // consulted by the onChange handler, which is internal; what a caller can
    // observe is that clearing it first makes the write stick and not clearing
    // it makes React's next render discard the write. This models that
    // observable behaviour: the step that calls `setValue('')` is the one whose
    // value survives.
    this._valueTracker = {
      tracked: attrs.value || '',
      cleared: false,
      setValue(v) {
        this.tracked = v;
        this.cleared = v === '';
      },
    };
  }

  getAttribute(name) {
    return this.attrs[name] === undefined ? null : this.attrs[name];
  }

  focus() {
    this.focused = true;
  }

  click() {
    if (this.disabled) throw new Error('clicked a disabled element');
    this.clicked = true;
    if (this.onclick) this.onclick();
  }

  dispatchEvent(event) {
    this.events.push(event.type);
    if (event.type !== 'input') return true;

    // This is the React behaviour the payment page was burned by, and the
    // reason both fills go through the native setter after clearing the
    // tracker. React compares the incoming value against the one its tracker
    // holds. If they match, it concludes nothing changed, fires no onChange,
    // and its next render puts the old value back. A step that assigns
    // `el.value` directly leaves the tracker holding the previous string, so
    // its write is silently reverted right here.
    if (!this._valueTracker.cleared) {
      // React saw no change it recognises, so its next render restores the
      // value it still believes the field holds. The write is gone, and
      // nothing threw: this is the silent failure, and on a login form it
      // reads to Venmo as an empty password.
      this.value = this.committed === undefined ? '' : this.committed;
      return true;
    }

    this.committed = this.value;
    this._valueTracker.tracked = this.value;
    this._valueTracker.cleared = false;
    return true;
  }

  // Enough of a selector engine for the selectors `auto::login` actually uses:
  // comma-separated lists of `tag[attr='value']` and bare tags.
  matches(selector) {
    return selector.split(',').some((part) => {
      part = part.trim();
      if (!part) return false;
      // `#id` as well as `tag[attr=...]`: the note field is `#payment-note`
      // on the live page and the payment steps ask for it that way.
      const m = part.match(/^([a-zA-Z]*)(#[A-Za-z0-9_-]+)?((\[[^\]]+\])*)$/);
      if (!m) return false;
      const [, tag, id, attrPart] = m;
      if (tag && tag.toUpperCase() !== this.tagName) return false;
      if (id && this.getAttribute('id') !== id.slice(1)) return false;
      const attrs = attrPart ? attrPart.match(/\[[^\]]+\]/g) || [] : [];
      return attrs.every((raw) => {
        const inner = raw.slice(1, -1);
        const eq = inner.indexOf('=');
        if (eq === -1) return this.getAttribute(inner) !== null;
        const name = inner.slice(0, eq);
        const want = inner.slice(eq + 1).replace(/^["']|["']$/g, '');
        return this.getAttribute(name) === want;
      });
    });
  }
}

class Document {
  // `text` lets a page state body copy that is not just its buttons' labels;
  // the payment page names the recipient in prose, not on a control.
  constructor(elements, text) {
    this.elements = elements;
    const self = this;
    this.body = {
      // A getter, not a snapshot: a page whose click removes a button must
      // read differently afterwards, and the confirmation step is precisely a
      // second read of the same page.
      get innerText() {
        return [text || '', ...self.elements.map((e) => e.innerText)].join(' ');
      },
    };
  }

  querySelector(selector) {
    return this.elements.find((e) => e.matches(selector)) || null;
  }

  querySelectorAll(selector) {
    return this.elements.filter((e) => e.matches(selector));
  }
}

// ---------------------------------------------------------------------------
// The pages
// ---------------------------------------------------------------------------

/// Venmo's sign-in form, as `auto::login`'s selectors describe it.
function signinPage() {
  return {
    url: 'https://id.venmo.com/signin',
    elements: [
      new Element('input', { name: 'username', type: 'text' }),
      new Element('input', { type: 'password', name: 'password' }),
      // No id, no test id, no aria-label. Text is the only handle.
      new Element('button', {}, 'Sign In'),
      // The decoy: a submit-typed button that is NOT the sign-in button. The
      // payment page had exactly this shape and `button[type='submit']` found
      // the wrong one, which is why the login steps match on text.
      new Element('button', { type: 'submit' }, 'Sign up for Venmo'),
      new Element('button', { type: 'submit' }, 'Accept cookies'),
    ],
  };
}

/// The 2FA challenge, after the form has been submitted.
function codePage() {
  return {
    url: 'https://id.venmo.com/signin/mfa',
    elements: [
      new Element('input', { name: 'code', autocomplete: 'one-time-code' }),
      new Element('button', {}, 'Submit'),
    ],
  };
}

/// A signed-in account page: no password box, and not a signin URL.
function accountPage() {
  return {
    url: 'https://account.venmo.com/',
    elements: [new Element('button', {}, 'Pay or Request')],
  };
}

/// The payment page, in the state that produced the 2026-09-05 false success.
///
/// Order `esc_2c0cef0587c47bafd201e104` drove a tab an earlier payment had
/// already left sitting on a filled form with the confirmation open. Every
/// check the driver had passed against it -- the recipient is named, the amount
/// field reads $2.01, a "Pay Jay Butera $2.01" button is present and enabled --
/// because all of them describe the *form*, and the form was right. Both clicks
/// then landed on buttons that did nothing, the whole sequence finished in
/// about three seconds, and the rail wrote the order paid.
///
/// So the buttons here are deliberately inert: `click()` is recorded and
/// nothing else happens. That is the honest model of the failure. A page whose
/// click removed the confirmation would be modelling a *working* payment, and
/// the test would prove nothing.
function stalePayPage() {
  const amount = new Element('input', { 'aria-label': 'Amount', value: '2.01' });
  // Already committed, the way a field an earlier drive filled would be.
  amount.committed = '2.01';
  amount._valueTracker.tracked = '2.01';
  const page = {
    url: 'https://account.venmo.com/pay?recipients=jay-butera',
    elements: [
      amount,
      new Element('textarea', { id: 'payment-note', value: 'thanks 5df45b72' }),
      // The audience control, on Venmo's default for a personal account. It
      // carries the current audience as its own text, which is the only handle
      // the live page gives it: no id, no test id, no aria-label, exactly like
      // the Pay and Confirm buttons beside it.
      audienceControl(),
      new Element('button', {}, 'Pay'),
      new Element('button', {}, 'Pay Jay Butera $2.01'),
      // The decoy from the 2026-09-02 run: permanently disabled, belongs to
      // something else, and waiting on it times out with the real
      // confirmation open.
      new Element('button', { disabled: true }, 'Confirm'),
    ],
    // The recipient has to be findable in the page text, as on the real page.
    text: 'Pay jay-butera',
  };
  // The control needs the page it lives on to open its menu into it.
  page.elements[2].page = page;
  return page;
}

/// Venmo's audience control, and the menu it opens.
///
/// Clicking it appends the three audience options to the page, the way a menu
/// renders; choosing one sets the control's text and takes the menu away. The
/// control starts on Public because that is what Venmo defaults a personal
/// account to, and it is what the live pay form showed on 2026-09-05.
function audienceControl(starting = 'Public') {
  const control = new Element('button', {}, starting);
  control.onclick = () => {
    const host = control.page;
    if (!host || control.menuOpen) return;
    control.menuOpen = true;
    for (const word of ['Public', 'Friends', 'Private']) {
      const option = new Element('button', { role: 'menuitem' }, word);
      option.onclick = () => {
        // Choosing an option sets the control and closes the menu.
        control.innerText = word;
        control.menuOpen = false;
        for (const o of host.menuOptions) {
          const at = host.elements.indexOf(o);
          if (at !== -1) host.elements.splice(at, 1);
        }
        host.menuOptions = [];
      };
      host.elements.push(option);
      host.menuOptions = (host.menuOptions || []).concat(option);
    }
  };
  return control;
}

/// The pay page whose audience menu does not take.
///
/// The failure this models is the audience version of the React-controlled
/// amount field: the menu opens, the option is clicked, and Venmo re-renders
/// the control underneath it so the form stays on Public while the script has
/// every reason to believe it took. Nothing throws. A driver that trusts its
/// own click here sends a tagged payment to the public feed.
function publicPayPage() {
  const page = stalePayPage();
  const control = page.elements.find((e) => e.innerText === 'Public');
  control.onclick = () => {
    const host = control.page;
    if (control.menuOpen) return;
    control.menuOpen = true;
    for (const word of ['Public', 'Friends', 'Private']) {
      const option = new Element('button', { role: 'menuitem' }, word);
      // The re-render: the menu closes and the control snaps back.
      option.onclick = () => {
        control.innerText = 'Public';
        control.menuOpen = false;
        for (const o of host.menuOptions) {
          const at = host.elements.indexOf(o);
          if (at !== -1) host.elements.splice(at, 1);
        }
        host.menuOptions = [];
      };
      host.elements.push(option);
      host.menuOptions = (host.menuOptions || []).concat(option);
    }
  };
  return page;
}

/// The same page, but where the confirmation click actually posts.
///
/// Venmo takes the payment form away when a payment goes through: the page
/// moves to the feed and the confirmation button goes with it. That is what
/// this models, and it is what the confirmation step keys on.
function livePayPage() {
  const page = stalePayPage();
  const confirm = page.elements.find((e) => e.innerText.startsWith('Pay Jay Butera'));
  confirm.onclick = () => {
    // The send posted, so the form is gone. Removing the confirmation button
    // is the observable half of that.
    page.elements.splice(page.elements.indexOf(confirm), 1);
  };
  return page;
}

const PAGES = {
  signin: signinPage,
  code: codePage,
  account: accountPage,
  stalepay: stalePayPage,
  publicpay: publicPayPage,
  livepay: livePayPage,
};

// ---------------------------------------------------------------------------
// Run one expression against one page
// ---------------------------------------------------------------------------
//
// Called as: node mock_login_page.js <page> <<< "<expression>"
// Answers a JSON line: {"ok":true,"value":...,"state":{...}} or {"ok":false,...}

// The native `value` setter, which is what `Object.getOwnPropertyDescriptor(
// HTMLInputElement.prototype, 'value').set` resolves to in a browser. It writes
// straight to the element and, crucially, does NOT touch React's tracker: that
// is why a fill has to clear the tracker itself.
function nativePrototype() {
  const proto = {};
  Object.defineProperty(proto, 'value', {
    configurable: true,
    set(v) {
      this.value = v;
    },
    get() {
      return this._raw;
    },
  });
  return proto;
}

// Real constructors, not bare `{prototype}` objects: the payment page's fill
// branches on `el instanceof HTMLTextAreaElement` to pick the right prototype,
// and `instanceof` against a plain object throws. The login steps never took
// that branch, which is why this went unnoticed until the payment steps ran
// here.
//
// `Symbol.hasInstance` decides the answer from the element's own tag, which is
// what the browser's real check comes down to for these two.
function nativeClass(tag) {
  const fn = function () {};
  fn.prototype = nativePrototype();
  Object.defineProperty(fn, Symbol.hasInstance, {
    value: (el) => !!el && el.tagName === tag,
  });
  return fn;
}

const NATIVE_INPUT = nativeClass('INPUT');
const NATIVE_TEXTAREA = nativeClass('TEXTAREA');

function main() {
  const pageName = process.argv[2];
  const build = PAGES[pageName];
  if (!build) {
    process.stdout.write(JSON.stringify({ ok: false, error: `no page ${pageName}` }));
    return;
  }

  const page = build();
  const document = new Document(page.elements, page.text);
  const location = { href: page.url };
  const input = require('fs').readFileSync(0, 'utf8');

  function evaluate(expression) {
    // eslint-disable-next-line no-new-func
    return new Function('document', 'location', 'HTMLInputElement', 'HTMLTextAreaElement', 'Event', `return (${expression});`)(
      document,
      location,
      NATIVE_INPUT,
      NATIVE_TEXTAREA,
      class Event {
        constructor(type) {
          this.type = type;
        }
      },
    );
  }

  function snapshot() {
    return page.elements.map((e) => ({
      tag: e.tagName,
      text: e.innerText,
      value: e.value,
      clicked: !!e.clicked,
      events: e.events,
    }));
  }

  // Sequence mode. One expression per process cannot express the payment flow:
  // the whole failure is about what the page looks like *after* a click, so the
  // steps have to run against one page that persists between them. A leading
  // `@@sequence` marks a run of expressions separated by a line of `@@`.
  if (input.startsWith('@@sequence')) {
    const steps = input.slice('@@sequence'.length).split(/^@@$/m).map((s) => s.trim()).filter(Boolean);
    const results = [];
    for (const expression of steps) {
      try {
        const value = evaluate(expression);
        results.push({ ok: true, value: value === undefined ? null : value });
      } catch (e) {
        results.push({ ok: false, error: String(e.message) });
        break;
      }
    }
    process.stdout.write(JSON.stringify({ ok: true, steps: results, href: location.href, state: snapshot() }));
    return;
  }

  let result;
  try {
    result = evaluate(input);
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(e.message) }));
    return;
  }

  process.stdout.write(
    JSON.stringify({
      ok: true,
      value: result === undefined ? null : result,
      href: location.href,
      state: snapshot(),
    }),
  );
}

main();
