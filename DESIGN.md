---
name: HoneyGrid Sentinel
description: Transit Wayfinding. Incidents are signed, colored and routed like a transit system.
colors:
  line-red: "#DA291C"
  line-orange: "#FF6319"
  line-yellow: "#FCCC0A"
  line-green: "#00843D"
  line-grey: "#A7A9AC"
  on-line-light: "#FFFFFF"
  on-line-dark: "#111214"
  band: "#0B0B0C"
  band-ink: "#F4F4F1"
  band-muted: "#9C9EA2"
  band-rule: "#34363A"
  night-ground: "#0F1012"
  night-surface: "#17181B"
  night-surface-2: "#1E2023"
  night-rule: "#2A2C30"
  night-rule-strong: "#3A3C41"
  night-ink: "#F4F4F1"
  night-ink-2: "#C9CACC"
  night-muted: "#A3A5A8"
  night-faint: "#6E7074"
  night-ghost: "#34363A"
  day-ground: "#F4F4F1"
  day-surface: "#FFFFFF"
  day-surface-2: "#ECECE8"
  day-rule: "#D6D6D1"
  day-rule-strong: "#B9B9B3"
  day-ink: "#111214"
  day-ink-2: "#2E3033"
  day-muted: "#5A5C60"
  day-faint: "#7C7E82"
  day-ghost: "#D9D9D4"
typography:
  display:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "clamp(44px, 7vw, 96px)"
    fontWeight: 800
    lineHeight: 0.95
    letterSpacing: "-0.035em"
    fontVariation: "'wdth' 92"
  headline:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "clamp(32px, 4.4vw, 56px)"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "-0.03em"
  numeral:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "40px"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "-0.03em"
    fontFeature: "'tnum' 1"
  title:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "20px"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "-0.01em"
  title-sm:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 800
    lineHeight: 1.1
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "'tnum' 1"
  body-lg:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "20px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.5
    letterSpacing: "0.01em"
  column-head:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "11px"
    fontWeight: 700
    letterSpacing: "0.06em"
  wordmark:
    fontFamily: "Archivo, Helvetica Neue, Helvetica, Arial, sans-serif"
    fontSize: "21px"
    fontWeight: 800
    letterSpacing: "-0.02em"
  mono:
    fontFamily: "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "0.92em"
    fontWeight: 600
    letterSpacing: "0"
rounded:
  sm: "2px"
  bullet: "50%"
spacing:
  "1": "4px"
  "2": "8px"
  "3": "12px"
  "4": "16px"
  "5": "24px"
  "6": "32px"
  "7": "48px"
  "8": "64px"
  "9": "96px"
components:
  sign-band:
    backgroundColor: "{colors.band}"
    textColor: "{colors.band-ink}"
    height: "64px"
    padding: "5px 24px 0"
  button:
    backgroundColor: "transparent"
    textColor: "{colors.night-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "36px"
  button-hover:
    backgroundColor: "{colors.night-surface-2}"
  button-primary:
    backgroundColor: "{colors.night-ink}"
    textColor: "{colors.night-ground}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "36px"
  button-primary-hover:
    backgroundColor: "{colors.night-ink-2}"
  button-danger-hover:
    backgroundColor: "{colors.line-red}"
    textColor: "{colors.on-line-light}"
  button-sm:
    height: "30px"
    padding: "0 12px"
  button-hero:
    height: "44px"
    padding: "0 24px"
  input:
    backgroundColor: "{colors.night-ground}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.sm}"
    padding: "0 12px"
    height: "40px"
  bullet-red:
    backgroundColor: "{colors.line-red}"
    textColor: "{colors.on-line-light}"
    rounded: "{rounded.bullet}"
    size: "30px"
  bullet-orange:
    backgroundColor: "{colors.line-orange}"
    textColor: "{colors.on-line-dark}"
    rounded: "{rounded.bullet}"
    size: "30px"
  bullet-yellow:
    backgroundColor: "{colors.line-yellow}"
    textColor: "{colors.on-line-dark}"
    rounded: "{rounded.bullet}"
    size: "30px"
  bullet-green:
    backgroundColor: "{colors.line-green}"
    textColor: "{colors.on-line-light}"
    rounded: "{rounded.bullet}"
    size: "30px"
  bullet-grey:
    backgroundColor: "{colors.line-grey}"
    textColor: "{colors.on-line-dark}"
    rounded: "{rounded.bullet}"
    size: "30px"
  chip-segment:
    backgroundColor: "transparent"
    textColor: "{colors.night-muted}"
    height: "30px"
    padding: "0 12px"
  chip-segment-pressed:
    backgroundColor: "{colors.night-ink}"
    textColor: "{colors.night-ground}"
  panel:
    backgroundColor: "{colors.night-surface}"
    rounded: "0"
  departure-row:
    backgroundColor: "transparent"
    height: "60px"
    padding: "0 16px"
  departure-row-hover:
    backgroundColor: "{colors.night-surface-2}"
---

# Design System: HoneyGrid Sentinel

## Overview

**Creative North Star: "Transit Wayfinding"**

Every intruder rides a line. The system treats triage as wayfinding: each incident is signed, colored and routed the way a metro system signs its lines, so an analyst reads threat the way a commuter reads a platform board, at a glance and without thinking. Where most SOC tools reach for neon radar chrome, this one is black enamel signage, a white neo-grotesk, square rules, and solid circular line bullets that carry the only color on the screen.

The density is a departures board: ruled rows, tabular figures, large numerals on a ruled strip, with no card grids. Night is the default, because the primary scene is analysts working late in a dim room. Daylight is a full alternative for reviewers and office light. The same world covers the operator console, the sign-in gate and the public landing page. The attacker-facing decoy page sits outside it by rule.

The recurring signature is the attacker's line: a vertical stroke in the incident's threat color with numbered stops in the margin and transfer stops where the attacker moves to another decoy. On the landing page the hero route turns and runs down the left gutter as a spine, and every section is a station on it.

**Key Characteristics:**
- Black enamel sign band in both themes, white top hairline, 4px bottom rule.
- Hue is the threat signal. Neutrals carry everything else.
- Five threat lines as solid circular bullets with numerals inside.
- Archivo for everything human; JetBrains Mono only for machine identifiers.
- 2px square rules, 2px radius. Circles only for bullets and stops.
- Flat, ruled surfaces. Soft shadow only on floating overlays.

## Colors

A neutral enamel-and-paper palette with five saturated transit-line colors reserved for threat.

### Primary
- **Line Red** (`line-red`): scores of 70 and above. It also colors the attacker's line on landing, the terminus station, and destructive or error states (the Isolate button border, invalid fields, sync failure). It is adjusted from the NYC red so white numerals pass WCAG AA 4.5:1.

### Secondary
- **Line Orange** (`line-orange`): scores 50–69, with dark numerals (`on-line-dark`).
- **Line Yellow** (`line-yellow`): scores 30–49, with dark numerals. At night it also serves as the focus ring, the text-selection fill and the brief flash on a newly arrived row.
- **Line Green** (`line-green`): scores 0–29, with white numerals. It is adjusted from the NYC green for the same AA reason as red.
- **Line Grey** (`line-grey`): safelisted incidents at any score, with dark numerals.

### Neutral
- **Enamel Black** (`band`), **Enamel White** (`band-ink`), **Enamel Muted** (`band-muted`), **Enamel Rule** (`band-rule`): the sign band, dialog heads, toasts, the demo bar, the landing closer and the footer. These values do not change between themes.
- **Night Ground** (`night-ground`), default page ground; **Night Surface** (`night-surface`), panels and dialogs; **Night Surface 2** (`night-surface-2`), hover and selected rows.
- **Night Rule** / **Night Rule Strong** (`night-rule`, `night-rule-strong`): dividers, then field and button strokes.
- **Night Ink** through **Night Faint** (`night-ink`, `night-ink-2`, `night-muted`, `night-faint`): four steps of text emphasis. **Night Ghost** (`night-ghost`) marks empty values (zero metrics, ghost bullets).
- **Daylight** (`day-*`): the same roles on warm paper (`day-ground`) with white surfaces and near-black ink. In daylight the focus ring turns to ink.

### Named Rules
**The Threat-Only Hue Rule.** Line colors mean threat. The documented exceptions are the yellow focus ring and selection at night, the yellow new-arrival flash, and red for destructive or error state. Nothing else gets a hue: no brand accent, no colored categories, no decorative tints.

**The Contrast-Adjusted Line Rule.** Red is `#DA291C` and green is `#00843D`, not the NYC-exact `#EE352E` / `#00933C`, because white numerals must meet 4.5:1. Orange, yellow and grey always carry dark numerals.

**The Band Mapping Rule.** 70+ red, 50–69 orange, 30–49 yellow, 0–29 green. A safelisted incident is grey regardless of score.

**The Night-First Rule.** Night is the default. Daylight applies through `data-theme="light"` or `prefers-color-scheme: light` (unless `data-theme="dark"` is set), and the stored `hg-theme` choice is applied before first paint.

## Typography

**Display Font:** Archivo (with Helvetica Neue, Helvetica, Arial)
**Body Font:** Archivo
**Label/Mono Font:** JetBrains Mono (with ui-monospace, SFMono-Regular, Menlo, Consolas)

**Character:** Archivo is a wide-axis neo-grotesk. It is set heavy and tight at signage scale and plain at body size, so it reads like station signs. JetBrains Mono appears only where a value is a machine's identifier.

### Hierarchy
- **Display** (800, clamp 44–96px, 0.95, -0.035em, width 92%): the landing hero headline only. Related monumental statements (the landing statement and closer at clamp 40–84px, the login headline at clamp 40–72px) share its weight and tracking.
- **Headline** (800, clamp 32–56px, 1.0, -0.03em): landing section heads, capped at about 18ch. Console view titles use 40px.
- **Numeral** (800, 40px, tabular): metric values on the ruled strip.
- **Title** (800, 20px) / **Title small** (800, 16px): panel bars, dialog heads, station names, spec heads.
- **Body** (400, 14px, 1.5, tabular figures on): console text. **Body large** (20px, 1.45–1.5) is for landing ledes and prose, up to 60–62ch.
- **Label** (600, 12px, +0.01em): field labels, captions, secondary lines.
- **Column head** (700, 11px, +0.06em, uppercase): table column headers, palette group names and drawer section heads. It is never used as an eyebrow above a headline.
- **Wordmark** (800 plus a 500 muted "Sentinel", 21px, -0.02em): drops to 18px below 600px.

### Named Rules
**The Mono-for-Machines Rule.** JetBrains Mono is reserved for machine identifiers: IP addresses, LAN addresses, ASNs, coordinates, paths, queries, token ids, raw headers and keyboard hints. Times, dates, counts, scores and measurements are set in Archivo with `tabular-nums`.

**The Signage Weight Rule.** Headings are 700–800 with negative tracking and balanced wrapping. Hierarchy comes from size and weight, never from color.

## Layout

The spacing scale runs in steps of 4, 8, 12, 16, 24, 32, 48, 64 and 96px. The console is a 200px rail plus a fluid view. The rail's active item has a 4px ink left border, which becomes a 4px bottom border when the rail turns into a horizontal tab strip below 860px. The main grid is split 7fr / 5fr: the departures board on the left, the route map and top origins on the right. It stacks below 1100px. Metrics sit on a strip with a 2px ink top rule and 1px dividers, four across, then two across below 860px.

Boards are grids of 60px rows with 1px rules between them. Columns drop progressively: the destination column goes at 1280px, and origin and actions go at 600px, where a two-line mobile summary takes over.

The landing page uses a 1280px wrap with a 24px gutter (16px below 720px). The hero route is a horizontal track with four stations that turns vertical below 720px. Below the hero, a 6px ink spine runs down the gutter. Each section is a station: a dot, a name, and a 180px label column (120px below 960px). Below 720px the station names are hidden, the dot alone marks the station, and nothing replaces the name as a label. The final section is the terminus. Its dot is red and the spine stops there.

The sign band is 64px tall and sticky in the console. Below 860px the scope, clock and button labels drop. Below 600px, search and deploy become 36px icon squares. Below 400px the console hides the wordmark text and keeps only the logo.

## Elevation & Depth

Surfaces are flat and separated by rules and tonal steps (ground, surface, surface 2), not by lift. Shadow appears only when something floats above the page: dialogs, the drawer, the user menu, map popups, toasts, the login panel and the landing's framed console excerpt. It is always soft and diffuse. There is no glow, no glass, no gradient and no hard offset shadow.

### Shadow Vocabulary
- **Overlay (night)** (`box-shadow: 0 16px 40px -12px rgba(0,0,0,0.6), 0 2px 6px rgba(0,0,0,0.35)`): anything that floats.
- **Overlay (day)** (`box-shadow: 0 16px 40px -14px rgba(17,18,20,0.28), 0 2px 6px rgba(17,18,20,0.08)`): the same role in daylight.
- **Band hairline** (`box-shadow: inset 0 3px 0 #0B0B0C, inset 0 5px 0 #F4F4F1`): draws the white top hairline on the enamel band. It is structural, not elevation.
- **Knockout ring** (`box-shadow: 0 0 0 4px var(--ground)`): cuts a bullet out of the line it rides.

### Named Rules
**The Flat-Ground Rule.** Anything that sits on the page is ruled, not lifted. Only overlays get the overlay shadow, and nothing ever glows.

## Shapes

Everything is square except threat and route marks. Rules are 2px for structure (panels, fields, buttons, dialog borders, metric tops) and 1px for row dividers. Corners are 2px on buttons, fields, tags and segmented controls. Panels, dialogs and the band are fully square. Circles are reserved for line bullets, route stops and signal dots. Route strokes (the attacker's line, the landing route and spine, the station index) are 6px solid bars. Stops are 22px rings with a 5px stroke, and transfer stops are 26px ink rings.

### Named Rules
**The Square Rule.** 2px rules, 2px radius. A circle means a line or a stop, and nothing else is round.

## Components

### Buttons
Signage-plain and confident.
- **Shape:** gently squared (2px) with a 2px stroke, 36px tall, 600 weight at 13px.
- **Default:** transparent with a strong-rule stroke. Hover fills with surface 2 and brightens the stroke. Pressing nudges the button 1px down.
- **Primary:** an ink fill with ground-colored text, which inverts per theme. On the band it becomes an enamel-white fill with black text.
- **Danger:** a red stroke that fills red with white text on hover. Used for Isolate.
- **Quiet:** no stroke until hover. **Small** is 30px, and **hero/CTA** buttons are 44px with 24px padding.
- **Focus:** a 2px outline with a 2px offset, yellow at night and ink in daylight. Inside the band it is always yellow.

### Line bullets
The threat mark. A solid circle with a centered 800-weight tabular numeral at 42% of the diameter. Sizes run from 22px (small) through 30px (default) and 44px (large) to 64px (extra large). Legends shrink to 10–14px. The **ghost** variant is a 2px ghost ring with faint text, used for zero or empty values.

### Chips (segmented filters)
A single 2px-bordered group with 2px dividers between segments. Segments are 30px tall and muted. The pressed segment inverts to an ink fill. Filter chips may lead with a 10px bullet.

### Cards / Containers
- **Corner Style:** square.
- **Background:** the surface tone on the ground.
- **Shadow Strategy:** none at rest (Flat-Ground Rule).
- **Border:** 2px rule. Panel bars are at least 48px tall with a 2px bottom rule and a 16px 800-weight title.
- **Internal Padding:** 16–24px.

### Inputs / Fields
- **Style:** 40px tall, ground-colored fill, 2px rule stroke, 2px radius, and a 12px 600-weight muted label above.
- **Focus:** the stroke turns ink, with no outline glow.
- **Error:** a red stroke. Form alerts get a 2px red border on a 10% red tint with a small red bullet.

### Navigation
- **Sign band:** an enamel-black band in both themes with a white 2px hairline near the top and a 4px enamel-rule bottom. The wordmark sits flush left (32px logo, "HoneyGrid" at 800, "Sentinel" in muted 500). The primary action sits on the right.
- **Rail:** 44px items, muted 600 at 13px. Hover moves to ink on surface. The current item gets ink text, a surface fill and a 4px ink left bar.

### Departures board (signature)
Rows are at least 60px tall: a bullet, a mono address with an origin line, origin, a "tool → decoy" destination with a faint arrow, and the time as a tabular Archivo figure with the date beneath. Hover and selection use surface 2, and the selected row adds a 4px ink inset bar. A new row flashes yellow at 22% and fades over 2.4s.

### Attacker line and drawer trunk (signature)
The incident drawer slides in from the right, 560px wide, with a 2px ink left border. Its enamel head carries a 6px bottom stripe in the incident's threat color: the trunk. Inside, the attacker's hits run as a 6px vertical line in that color. Each hit is a ringed stop with its sequence number in the margin. A stop where the attacker changes decoy is a larger ink transfer ring with an uppercase "transfer" tag. The current hit's stop is filled solid. A three-up summary above the line sits on a 2px ink top rule.

### Dialogs, palette, toasts
Dialogs have a 2px ink border, the overlay shadow, a scrim backdrop and an enamel head. Modals rise 12px over 280ms. The command palette is 640px wide with a 56px input, and the selected option inverts to an ink fill. Toasts are enamel-black strips at the bottom right with a small leading bullet.

### Motion
One exponential ease-out (`cubic-bezier(0.16, 1, 0.3, 1)`) at 120ms for state changes, 280ms for rises and 520ms for the drawer. On landing, a single red bullet rides the hero route station to station once and holds at Contain. The newest map pin pulses its ring three times. With `prefers-reduced-motion`, everything settles at once and the rider starts at Contain.

## Do's and Don'ts

### Do:
- **Do** map threat as 70+ red, 50–69 orange, 30–49 yellow, 0–29 green, and grey for any safelisted incident.
- **Do** use `#DA291C` and `#00843D` for red and green so white numerals pass 4.5:1. Put dark numerals on orange, yellow and grey.
- **Do** keep the sign band enamel black in both themes, with the white top hairline, the 4px bottom rule, and a 21px wordmark (18px below 600px, logo only below 400px).
- **Do** set IPs, ASNs, coordinates, paths, queries, token ids and raw headers in JetBrains Mono. Set times, dates, counts and measurements in Archivo with `tabular-nums`.
- **Do** draw an incident's history as the attacker line: a vertical stroke in its threat color, numbered stops in the margin, and transfer stops where the decoy changes. Carry the same color as the drawer's trunk stripe.
- **Do** let landing sections hang on the gutter spine as stations. On mobile, hide the station names and let the dot mark the station.
- **Do** use 2px rules and 2px radius. Keep circles for bullets and stops.
- **Do** default to night (`#0F1012` ground) and offer daylight through `data-theme` or `prefers-color-scheme`.

### Don't:
- **Don't** apply this world to `decoy.html`. The attacker-facing decoy page stays a bland corporate 401 with no HoneyGrid tokens, fonts, band or colors, because stealth outranks brand.
- **Don't** give hue to anything but threat, apart from the yellow focus, selection and new-arrival flash, and red for destructive or error state.
- **Don't** use glow, glass, gradients or hard offset shadows. Shadow belongs to floating overlays only.
- **Don't** set times, counts or scores in monospace.
- **Don't** put kickers or eyebrow labels above headlines. Uppercase 11px is for column headers and section heads only.
- **Don't** replace the departures board with card grids or feature-card trios.
