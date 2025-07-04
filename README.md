Master Thesis


## Custom Mix Format

This fork introduces a simplified mix packet that embeds executable
instructions directly in the sphinxHeader. A packet now has the following
layout:

```
[Alpha | encrypted instructions | MAC | payload]
```

The instructions are interpreted by each hop to process the enclosed
packet, allowing different mix formats (e.g. Sphinx or PolySphinx) to be
emulated
