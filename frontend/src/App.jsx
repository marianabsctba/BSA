import React from "react";
import LegacyConsole from "./LegacyConsole.jsx";

// Thin composition entrypoint. Feature slices are migrated out of
// LegacyConsole in CI-guarded steps to keep runtime behavior stable.
export default function App(){
 return <LegacyConsole/>;
}
