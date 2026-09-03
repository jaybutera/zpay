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
      const m = part.match(/^([a-zA-Z]*)((\[[^\]]+\])*)$/);
      if (!m) return false;
      const [, tag, attrPart] = m;
      if (tag && tag.toUpperCase() !== this.tagName) return false;
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
  constructor(elements) {
    this.elements = elements;
    this.body = { innerText: elements.map((e) => e.innerText).join(' ') };
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

const PAGES = { signin: signinPage, code: codePage, account: accountPage };

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

const NATIVE_INPUT = { prototype: nativePrototype() };
const NATIVE_TEXTAREA = { prototype: nativePrototype() };

function main() {
  const pageName = process.argv[2];
  const build = PAGES[pageName];
  if (!build) {
    process.stdout.write(JSON.stringify({ ok: false, error: `no page ${pageName}` }));
    return;
  }

  const page = build();
  const document = new Document(page.elements);
  const location = { href: page.url };
  const expression = require('fs').readFileSync(0, 'utf8');

  let result;
  try {
    // eslint-disable-next-line no-new-func
    result = new Function('document', 'location', 'HTMLInputElement', 'HTMLTextAreaElement', 'Event', `return (${expression});`)(
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
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(e.message) }));
    return;
  }

  process.stdout.write(
    JSON.stringify({
      ok: true,
      value: result === undefined ? null : result,
      href: location.href,
      state: page.elements.map((e) => ({
        tag: e.tagName,
        text: e.innerText,
        value: e.value,
        clicked: !!e.clicked,
        events: e.events,
      })),
    }),
  );
}

main();
