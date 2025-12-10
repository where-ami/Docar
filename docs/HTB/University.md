---
sidebar_position: 1
---

# University

Docusaurus is a **static-site-generator** (also called **[Jamstack](https://jamstack.org/)**).

It builds your site as simple **static HTML, JavaScript and CSS files**.

## Build your site

Basic port scan **for production**:

```bash
nmap -F -A 10.10.11.10 -T4 -oN namp.fast
```

The static files are generated in the `build` folder.

## Service discovery

Test your production build locally:

```bash
npm run serve
```

The `build` folder is now served at [http://localhost:3000/](http://localhost:3000/).

You can now deploy the `build` folder **almost anywhere** easily, **for free** or very small cost (read the **[Deployment Guide](https://docusaurus.io/docs/deployment)**).
