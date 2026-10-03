from pathlib import Path
import re

legacy = Path("frontend/src/LegacyConsole.jsx")
text = legacy.read_text(encoding="utf-8")

import_anchor = 'import{pollActiveRequest}from"./activeRequest.js";\n'
login_render = 'if(!authenticated)return <Login login={login} setLogin={setLogin} onSubmit={doLogin} error={loginError} locale={locale} setLocale={setLocale}/>;'
login_component = re.compile(r'function Login\(\{login,setLogin,onSubmit,error,locale,setLocale\}\)\{.*?\nfunction AttackRadar\(', re.S)

if 'import LoginView from "./components/LoginView.jsx";' not in text:
    if import_anchor not in text:
        raise SystemExit("activeRequest import anchor not found")
    text = text.replace(import_anchor, import_anchor + 'import LoginView from "./components/LoginView.jsx";\n', 1)

if login_render not in text:
    raise SystemExit("legacy Login render anchor not found")
text = text.replace(
    login_render,
    'if(!authenticated)return <LoginView login={login} setLogin={setLogin} onSubmit={doLogin} error={loginError} locale={locale} setLocale={setLocale}/>;',
    1,
)

match = login_component.search(text)
if not match:
    raise SystemExit("legacy Login component block not found")
text = login_component.sub('function AttackRadar(', text, count=1)

if 'function Login(' in text:
    raise SystemExit("legacy Login component still present after migration")
if '<Login ' in text:
    raise SystemExit("legacy Login render still present after migration")

legacy.write_text(text, encoding="utf-8")

# This migration is deliberately one-shot. The workflow removes both itself and
# this script in the same commit after tests pass.
