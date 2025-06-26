Master Thesis


## Custom Mix Format

This fork introduces a simplified mix packet that embeds executable
instructions directly in the header. A packet now has the following
layout:

```
[Alpha | MAC over instructions | encrypted instructions | onion instructions | original packet]
```

The instructions are interpreted by each hop to process the enclosed
packet, allowing different mix formats (e.g. Sphinx or PolySphinx) to be
emulated
