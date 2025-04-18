/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  // By default, Docusaurus generates a sidebar from the docs folder structure
  //tutorialSidebar: [{type: 'autogenerated', dirName: '.'}],

  // But you can create a sidebar manually
  
  artiSidebar: [
    {
      type: 'doc',
      label: 'Getting Started with Arti',
      id: 'getting-started'
    },
    {
      type: 'category',
      label: 'Guides',
      items: ['guides/guides','guides/compiling-arti', 'guides/safer-build-options', 'guides/starting-arti', 'guides/configuring-arti', 'guides/connecting-to-onion', 'guides/troubleshooting', 'guides/compatibility', 'guides/capability-limitations', 'guides/cli-reference', 
    {
      "type": "link",
      "label": "Configuration Reference",
      "href": "https://tpo.pages.torproject.net/core/doc/rust/arti/index.html#configuration"
    }]
    },
    {
      type: 'category',
      label: 'Censorship',
      items: ['censorship/bridges', 'censorship/pluggable-transports']
    },
    {
      type: 'category',
      label: 'Integrating Arti',
      items: ['integrating-arti/integrating-arti',
        {
          type: 'category',
          label: 'Custom Wrappers',
          items: ['integrating-arti/custom-wrappers/iOS', 'integrating-arti/custom-wrappers/android']
        },
        'integrating-arti/using-tor', 'integrating-arti/examples',
      ]
    },
    {
      type: 'category',
      label: 'Contributing to Arti',
      items: [
        'contributing/contributing', 'contributing/code-of-conduct', 'contributing/support-policy',
        {
          type: 'category',
          label: 'For Developers',
          items: ['contributing/for-developers/project-status', 'contributing/for-developers/architecture', 'contributing/for-developers/config-options','contributing/for-developers/crates', 'contributing/for-developers/exposing-api', 'contributing/for-developers/testing', 'contributing/for-developers/logging']
        }
      ]
    },
    {
      type: 'link',
      label: 'Changelog',
      href: 'https://gitlab.torproject.org/tpo/core/arti/-/blob/main/CHANGELOG.md'
    },
    {
      type: 'link',
      label: 'Arti Rustdoc',
      href: 'https://tpo.pages.torproject.net/core/doc/rust/arti_client/index.html'
    },
    {
      type: 'link',
      label: 'Arti Coverage Reports',
      href: 'https://tpo.pages.torproject.net/core/arti/coverage/'
    },
    {
      type: 'category',
      label: 'Resources',
      items: [
        {
          type: 'link',
          label: 'Glossary',
          href: 'https://spec.torproject.org/glossary.html'
        },
        {
          type: 'link',
          label: 'Tor Specifications',
          href: 'https://spec.torproject.org'
        } 
      ]
    }
  ]
};

module.exports = sidebars;
