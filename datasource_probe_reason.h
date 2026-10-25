/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Which capture-helper probe declines are worth showing the operator.
 *
 * When a helper declines a source definition it writes a reason into `msg`.
 * Without this, the server discards it (upstream `complete_probe()` takes the
 * reason as `std::string in_reason __attribute__((unused))`), so an operator
 * gets only
 *
 *     ERROR: Unable to find driver for 'celldiag:replay=...'.  Make sure that
 *     any required plugins are loaded, ...
 *
 * which is the same sentence for a typo, a missing helper package and an
 * unplugged radio.
 *
 * Why a discriminator is needed at all: the cell helpers only write a reason
 * for a near-miss on their own prefix, but the stock helpers do not behave that
 * way.  Every builder is probed with every definition, and:
 *
 *   capture_linux_wifi.c:1405   "Expected an interface with a standard network
 *                                API, skipping"
 *   capture_framework.c:1739    "Source does not support probing"
 *
 * are written for any foreign definition. Surfacing every non-empty reason would
 * give `-c celldiag-typo` a paragraph from every helper on the system.
 *
 * So the ownership test is applied HERE, where the information actually is: the
 * tracker knows the definition, and each probing datasource knows its builder's
 * source type. A helper's reason is shown only when its driver plausibly OWNS
 * the definition -- the definition's interface begins with that driver's type.
 *
 * Kept header-only and free of every Kismet global on purpose: the decision is
 * the part with logic in it, and it can then be exercised by a selftest that
 * compiles with a bare `c++` on a host that cannot `./configure` this tree.
 */

#ifndef __DATASOURCE_PROBE_REASON_H__
#define __DATASOURCE_PROBE_REASON_H__

#include <cctype>
#include <string>

/* The interface portion of a source definition: everything before the first
 * ':'. `celldiag-350123456789012:replay=/tmp/x.dlf` -> `celldiag-350123456789012`.
 */
inline std::string datasource_definition_interface(const std::string& definition) {
    auto colon = definition.find(':');
    if (colon == std::string::npos)
        return definition;
    return definition.substr(0, colon);
}

/* Does `source_type` plausibly OWN `definition`?
 *
 * True when the definition's interface begins with the driver's type name AND
 * the next character is not alphanumeric -- so `celldiag` owns `celldiag` and
 * `celldiag-350123456789012`, but does not own a hypothetical `celldiagnostics`.
 * The boundary test is what keeps this from being a loose substring match; a
 * plain prefix compare would claim definitions belonging to a differently-named
 * driver that happens to start the same way.
 *
 * Deliberately NOT a match on the reason's content. Judging a decline by what
 * it says would make the operator's visibility depend on a helper's wording,
 * which is the thing most likely to change and least likely to be tested.
 */
inline bool datasource_reason_is_own_definition(const std::string& definition,
        const std::string& source_type) {

    /* Load-bearing.  An empty string is a prefix of every string, and when the
     * interface is empty too the equal-length branch below returns true -- so
     * a builder with an unset source type would claim `:replay=/x.dlf` and
     * surface its reason for it. Pinned by that exact input in the selftest;
     * the obvious test (`"celldiag"` vs `""`) does NOT pin it, because the
     * boundary test rejects that one on its own. */
    if (source_type.empty() || definition.empty())
        return false;

    /* Not independently load-bearing today.  ':' is not alphanumeric, so the
     * boundary test below already refuses to match across it: matching the
     * whole definition instead of the interface changes no answer in the
     * selftest.  The only separating input is a source_type that itself
     * contains a colon, which no driver has.
     *
     * Kept because it makes the rule mean what its name says -- the DEFINITION'S
     * INTERFACE begins with the driver's type -- so a future change to the
     * boundary rule cannot silently start matching into the options. */
    const auto iface = datasource_definition_interface(definition);

    /* Also defensive rather than decisive: `iface[iface.length()]` is a
     * defined '\0', which mismatches any character a real source type can
     * contain, so the loop below already returns false first. Kept so the
     * bound is stated rather than inherited from that guarantee. */
    if (iface.length() < source_type.length())
        return false;

    for (size_t i = 0; i < source_type.length(); i++) {
        if (std::tolower((unsigned char) iface[i]) !=
                std::tolower((unsigned char) source_type[i]))
            return false;
    }

    if (iface.length() == source_type.length())
        return true;

    return !std::isalnum((unsigned char) iface[source_type.length()]);
}

#endif
