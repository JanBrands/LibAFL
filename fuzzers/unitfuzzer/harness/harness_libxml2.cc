/**
 * note: Based on libxml2/doc/examples/parse3.c
 * author: Jan Brandstetter
 */

#include <stdio.h>
#include <stdint.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/**
 * Harenss function
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    xmlDocPtr doc; /* the resulting document tree */

    /*
     * The document being in memory, it have no base per RFC 2396,
     * and the "noname.xml" argument will serve as its base.
     */
    doc = xmlReadMemory((const char*)data, size, "noname.xml", NULL, 0);
    if (doc == NULL) {
	    return 1;
    }
    xmlFreeDoc(doc);

    return 0;
}
