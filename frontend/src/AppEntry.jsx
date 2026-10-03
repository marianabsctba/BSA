import React from "react";
import LegacyConsole from "./LegacyConsole.jsx";

// Transitional composition seam: domain views are migrated out of LegacyConsole
// in small CI-guarded slices while runtime behavior remains stable.
export default function AppEntry(){
 return <LegacyConsole/>;
}
