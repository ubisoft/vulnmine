# Notes for vulnmine developers

This article gives some quick notes for people interested in customizing /
developing vulnmine.

## Plugins

### Overview

There are two plugins provided:

* _plugin1.py_: Shows how complementary information can be used to augment the SCCM host record.
* _plugin2._: Shows how to produce customized statistics and output files.

The plugins use the [python yapsy framework](http://yapsy.sourceforge.net/)

Plugins are defined using the _*.yapsy-plugin_ file.
In vulnmine, plugins are loaded by utils _load_plugins()_ function. The plugin manager object is initialized here.

The mainline vulnmine.py calls the plugins (in the _rd_sccm_hosts()_ and _output_stats()_ functions.)
