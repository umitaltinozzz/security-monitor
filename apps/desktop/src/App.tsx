import { useEffect, useState } from "react";
import en from "./locales/en.json";
import tr from "./locales/tr.json";
import "./app.css";

const messages = { en, tr };
type Language = keyof typeof messages;

function preferredLanguage(): Language {
  return navigator.language.toLowerCase().startsWith("tr") ? "tr" : "en";
}

export function App() {
  const [language, setLanguage] = useState<Language>(preferredLanguage);
  const copy = messages[language];
  const nextLanguage: Language = language === "en" ? "tr" : "en";

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  return (
    <main className="app-shell">
      <header className="app-header">
        <a className="brand" href="./" aria-label={copy.appName}>
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>{copy.appName}</span>
        </a>
        <button
          className="language-button"
          type="button"
          aria-label={copy.languageToggleLabel}
          onClick={() => setLanguage(nextLanguage)}
        >
          {messages[nextLanguage].languageName}
        </button>
      </header>
      <section className="welcome-card" aria-labelledby="welcome-title">
        <div className="eyebrow">{copy.appName}</div>
        <h1 id="welcome-title">{copy.welcomeTitle}</h1>
        <p>{copy.welcomeDescription}</p>
      </section>
    </main>
  );
}
