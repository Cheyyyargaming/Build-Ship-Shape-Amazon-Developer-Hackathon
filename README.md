# Aha Academy

**Big ideas, made easy.** A TV-first learning app concept for students who want school topics explained simply and visually.

## Prototype

This TV-first demo includes:

- Username and password registration/sign-in, with grade stored on the learner account.
- A remote-friendly learning home screen with large topic cards, search, and subject filters.
- 105 lessons across 10 subjects: five original lessons plus 100 new topics in math, science, English, history, geography, technology, nature, health, arts, and life skills.
- Every new topic has a short explanation, an everyday example, an original mini-story, and a multiple-choice knowledge check.
- A “Today’s 5 topics” spotlight rotates through the 100 new lessons by local calendar date; all lessons remain available in the library.
- The added lesson catalog is shared between the website and Node backend, so completion progress is saved per account in SQLite.
- A daily three-task plan that changes by weekday and saves check-offs per account.
- An interactive “Ask Aha” study buddy concept with topic-based sample explanations and quiz prompts.
- Lesson completion and daily-task progress saved in SQLite per account.
- Keyboard and D-pad navigation with a visible focus state.

The password is stored as a salted scrypt hash, never as readable text. Login sessions use an HTTP-only cookie and are stored server-side as token hashes. The tutor replies are still sample responses selected from the lesson topic; connect an AI service through a backend to support open-ended answers.

The new “Find a hidden planet” lesson is an original explanation based on [NASA Science’s transit overview](https://science.nasa.gov/exoplanets/whats-a-transit/). It lets students move a planet across a star and see an exaggerated brightness dip appear in a light-curve graph. The visual exaggeration is labeled in the lesson so it is not mistaken for real transit scale.

## Run it

Requires Node.js 24.15 or later. No packages need to be installed; SQLite is provided by Node's built-in `node:sqlite` module.

```powershell
cd "D:\AMAZON"
node server.js
```

Then open `http://localhost:4173`. Register a username, password (at least 8 characters), and grade. Use arrow keys to navigate, Enter/Space to choose, and Escape/Backspace to close a lesson or tutor. The browser and mouse also work.

The server creates `aha-academy.sqlite` beside `server.js`; this file is ignored by Git. Accounts and progress stay in that database on this computer.

## Fire TV demo path

This is a local development server, not a production account service. It binds only to `127.0.0.1` by default; don't expose it to a network or the internet. A Fire TV demo needs a properly secured server reachable by the TV, plus a packaged app running on an actual Fire TV or the Vega Virtual Device. Amazon documents app porting and device testing in [Amazon Devices Builder Tools](https://developer.amazon.com/docs/adbt/home) and [Run Your App on Vega Virtual Device or Fire TV](https://developer.amazon.com/docs/vega/0.24/run-apps).

The TV layout keeps primary actions large, puts them inside a safe screen margin, and shows focus as students move with the D-pad, following [Amazon's Fire TV design guidelines](https://developer.amazon.com/docs/fire-tv/design-and-user-experience-guidelines.html).
