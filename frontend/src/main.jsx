import React from "react";
import{createRoot}from"react-dom/client";
import App from "./App";
import ProductBoundary from "./ProductBoundary";
import ProductExperience from "./ProductExperience";
import "./styles.css";
import "./product-ux.css";

createRoot(document.getElementById("root")).render(
 <React.StrictMode>
  <ProductBoundary>
   <ProductExperience><App/></ProductExperience>
  </ProductBoundary>
 </React.StrictMode>
);
