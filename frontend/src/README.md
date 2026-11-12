# Frontend Application Shell

## Overview
Core React application module providing the application bootstrap entry point, top-level routing, sidebar navigation shell, operator authentication session storage, and global CSS styling.

## Interface
- [main.jsx:createRoot] Application entry point rendering root App within React.StrictMode into document.getElementById('root')
- [App.jsx:App] Root application layout component wrapping BrowserRouter, managing global operator authentication state, sidebar navigation, and route definitions
- [App.jsx:NavItem] Internal sidebar navigation link component binding React Router Link with active route styling
- components: [./components/README.md](./components/README.md) - React UI component library for fleet management and monitoring

## Invariants
- [App.jsx:operatorToken] Default operator token is initialized from sessionStorage('rmm_operator_token') or fallback 'rmm_admin_dev_token_2026'
- [App.jsx:operatorToken] Any change to operator token in UI immediately synchronizes to sessionStorage('rmm_operator_token')
- [App.jsx:Routes] Default route '/' strictly redirects to '/agents' via Navigate component

## Side Effects
- [App.jsx:fetchPrincipal] Dispatches HTTP GET /api/v1/users/me upon operatorToken state change to validate identity and role
- [App.jsx:handleTokenChange] Writes updated token to browser sessionStorage
- [main.jsx:index.css] Imports and applies global CSS styles to the DOM

## Verification
- Run: `npm run build`
