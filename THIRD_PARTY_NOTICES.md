# Third-Party Software Notices

Talaria incorporates or depends on third-party open-source software.

Talaria itself is licensed under the GNU Affero General Public License,
Version 3 only (`AGPL-3.0-only`). The Talaria license does not replace,
modify, or supersede the licenses applicable to third-party software.
Each third-party component remains subject to its own license terms.

This file is based on the dependency graph declared in the repository's
current `go.mod`. Exact versions are listed below. `go.sum` entries that do
not correspond to a current `go.mod` requirement are not treated as current
Talaria dependencies merely because a checksum remains in `go.sum`.

## Dependency Summary

| Component | Version | Dependency Type | License |
|---|---|---|---|
| `gvisor.dev/gvisor` | `v0.0.0-20260122175437-89a5d21be8f0` | Direct | Apache-2.0; some upstream files carry MIT or BSD terms |
| `github.com/things-go/go-socks5` | `v0.1.1` | Direct | MIT |
| `golang.org/x/crypto` | `v0.52.0` | Direct | BSD-3-Clause |
| `golang.org/x/net` | `v0.55.0` | Direct | BSD-3-Clause |
| `golang.org/x/sys` | `v0.45.0` | Direct | BSD-3-Clause |
| `github.com/google/btree` | `v1.1.3` | Indirect | Apache-2.0 |
| `github.com/davecgh/go-spew` | `v1.1.2-0.20180830191138-d8f796af33cc` | Indirect; currently unreachable | ISC |
| `github.com/pmezard/go-difflib` | `v1.0.1-0.20181226105442-5d4384ee4fb2` | Indirect; currently unreachable | BSD-3-Clause |
| `golang.org/x/exp` | `v0.0.0-20260529124908-c761662dc8c9` | Indirect | BSD-3-Clause |
| `golang.org/x/time` | `v0.15.0` | Indirect | BSD-3-Clause |

`github.com/davecgh/go-spew` and `github.com/pmezard/go-difflib` remain
declared as indirect requirements in `go.mod`, although `go mod why -m`
reports that the current main module does not need them. They are retained in
this source-release inventory for completeness and are not represented as
reachable or linked runtime dependencies.

The current `go.mod` does **not** declare `golang.zx2c4.com/wireguard`, so
WireGuard Go is not included in this notice. If WireGuard source is vendored,
copied, or otherwise incorporated outside the Go module graph, its applicable
license notice must be added separately.

---

## 1. gVisor

- **Component:** `gvisor.dev/gvisor`
- **Version:** `v0.0.0-20260122175437-89a5d21be8f0`
- **Upstream:** https://github.com/google/gvisor
- **Primary repository license:** Apache License 2.0 (`Apache-2.0`)
- **Use in Talaria:** user-space TCP/IP networking used by Talaria flow handling
- **Talaria modifications to upstream source:** none represented by `go.mod`;
  any vendored or copied modifications must be documented separately.

The upstream gVisor license states that the repository is primarily licensed
under Apache License 2.0 and that some individual files carry MIT or BSD
license terms identified in those files. Accordingly:

1. the Apache License 2.0 text is reproduced below;
2. if a Talaria source distribution vendors or copies gVisor files, all
   applicable file-level copyright and license notices must be retained;
3. if a Talaria binary incorporates a gVisor file carrying MIT or BSD terms,
   the corresponding file-level copyright notice must also be reproduced in
   the documentation or other materials accompanying that binary where the
   applicable license requires it; and
4. if Talaria modifies an Apache-2.0-licensed gVisor file, that file must carry
   a prominent notice stating that it was changed.

### gVisor file-level MIT terms

For any gVisor file whose header identifies the MIT license, retain that
file's own copyright notice together with the following permission notice:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


### gVisor file-level BSD terms

For any gVisor file whose header identifies the BSD license, retain that
file's own copyright notice together with the following terms:

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the applicable file-level
  copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the applicable file-level
  copyright notice, this list of conditions and the following disclaimer in
  the documentation and/or other materials provided with the distribution.

* Neither the name of Google Inc. nor the names of its contributors may be
  used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


---

## 2. Google B-Tree

- **Component:** `github.com/google/btree`
- **Version:** `v1.1.3`
- **Upstream:** https://github.com/google/btree
- **License:** Apache License 2.0 (`Apache-2.0`)
- **Dependency type:** Indirect

The Apache License 2.0 text applicable to this component is reproduced below.
Any copyright, patent, trademark, or attribution notices present in upstream
source files that are copied or vendored into Talaria must be retained.

---

## 3. go-socks5

- **Component:** `github.com/things-go/go-socks5`
- **Version:** `v0.1.1`
- **Upstream:** https://github.com/things-go/go-socks5
- **License:** MIT
- **Copyright:** Copyright (c) 2014 Armon Dadgar
- **Dependency type:** Direct

### MIT License — go-socks5

Copyright (c) 2014 Armon Dadgar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


---

## 4. Go Supplementary Modules

The following Go modules are used by Talaria and are licensed under the BSD
3-Clause license:

| Component | Version | Dependency Type |
|---|---|---|
| `golang.org/x/crypto` | `v0.52.0` | Direct |
| `golang.org/x/net` | `v0.55.0` | Direct |
| `golang.org/x/sys` | `v0.45.0` | Direct |
| `golang.org/x/exp` | `v0.0.0-20260529124908-c761662dc8c9` | Indirect |
| `golang.org/x/time` | `v0.15.0` | Indirect |

- **Upstream organization:** The Go Authors / Go project
- **Canonical repositories:** `https://go.googlesource.com/`
- **License:** BSD 3-Clause (`BSD-3-Clause`)

### BSD 3-Clause License — The Go Authors

Copyright 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of Google LLC nor the names of its contributors may be
  used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


---

## 5. Declared but Currently Unreachable Modules

The following modules are declared as indirect requirements in `go.mod`, but
are not reachable from the current package dependency graph. Their notices are
included because they remain part of the declared module inventory.

### go-spew (ISC)

- **Component:** `github.com/davecgh/go-spew`
- **Version:** `v1.1.2-0.20180830191138-d8f796af33cc`
- **Copyright:** Copyright (c) 2012-2016 Dave Collins <dave@davec.name>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

### go-difflib (BSD-3-Clause)

- **Component:** `github.com/pmezard/go-difflib`
- **Version:** `v1.0.1-0.20181226105442-5d4384ee4fb2`
- **Copyright:** Copyright (c) 2013, Patrick Mezard

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* The names of its contributors may not be used to endorse or promote
  products derived from this software without specific prior written
  permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


---

# Apache License 2.0

The following license applies to the Apache-2.0 components identified above,
including gVisor's Apache-2.0-licensed files and `github.com/google/btree`.

Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction, and
distribution as defined by Sections 1 through 9 of this document.

"Licensor" shall mean the copyright owner or entity authorized by the
copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all other
entities that control, are controlled by, or are under common control with
that entity. For the purposes of this definition, "control" means (i) the
power, direct or indirect, to cause the direction or management of such
entity, whether by contract or otherwise, or (ii) ownership of fifty percent
(50%) or more of the outstanding shares, or (iii) beneficial ownership of
such entity.

"You" (or "Your") shall mean an individual or Legal Entity exercising
permissions granted by this License.

"Source" form shall mean the preferred form for making modifications,
including but not limited to software source code, documentation source, and
configuration files.

"Object" form shall mean any form resulting from mechanical transformation
or translation of a Source form, including but not limited to compiled object
code, generated documentation, and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or Object form,
made available under the License, as indicated by a copyright notice that is
included in or attached to the work (an example is provided in the Appendix
below).

"Derivative Works" shall mean any work, whether in Source or Object form,
that is based on (or derived from) the Work and for which the editorial
revisions, annotations, elaborations, or other modifications represent, as a
whole, an original work of authorship. For the purposes of this License,
Derivative Works shall not include works that remain separable from, or merely
link (or bind by name) to the interfaces of, the Work and Derivative Works
thereof.

"Contribution" shall mean any work of authorship, including the original
version of the Work and any modifications or additions to that Work or
Derivative Works thereof, that is intentionally submitted to Licensor for
inclusion in the Work by the copyright owner or by an individual or Legal
Entity authorized to submit on behalf of the copyright owner. For the purposes
of this definition, "submitted" means any form of electronic, verbal, or
written communication sent to the Licensor or its representatives, including
but not limited to communication on electronic mailing lists, source code
control systems, and issue tracking systems that are managed by, or on behalf
of, the Licensor for the purpose of discussing and improving the Work, but
excluding communication that is conspicuously marked or otherwise designated
in writing by the copyright owner as "Not a Contribution."

"Contributor" shall mean Licensor and any individual or Legal Entity on behalf
of whom a Contribution has been received by Licensor and subsequently
incorporated within the Work.

2. Grant of Copyright License.

Subject to the terms and conditions of this License, each Contributor hereby
grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
irrevocable copyright license to reproduce, prepare Derivative Works of,
publicly display, publicly perform, sublicense, and distribute the Work and
such Derivative Works in Source or Object form.

3. Grant of Patent License.

Subject to the terms and conditions of this License, each Contributor hereby
grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
irrevocable (except as stated in this section) patent license to make, have
made, use, offer to sell, sell, import, and otherwise transfer the Work, where
such license applies only to those patent claims licensable by such Contributor
that are necessarily infringed by their Contribution(s) alone or by
combination of their Contribution(s) with the Work to which such
Contribution(s) was submitted. If You institute patent litigation against any
entity (including a cross-claim or counterclaim in a lawsuit) alleging that
the Work or a Contribution incorporated within the Work constitutes direct or
contributory patent infringement, then any patent licenses granted to You
under this License for that Work shall terminate as of the date such
litigation is filed.

4. Redistribution.

You may reproduce and distribute copies of the Work or Derivative Works
thereof in any medium, with or without modifications, and in Source or Object
form, provided that You meet the following conditions:

(a) You must give any other recipients of the Work or Derivative Works a copy
of this License; and

(b) You must cause any modified files to carry prominent notices stating that
You changed the files; and

(c) You must retain, in the Source form of any Derivative Works that You
distribute, all copyright, patent, trademark, and attribution notices from the
Source form of the Work, excluding those notices that do not pertain to any
part of the Derivative Works; and

(d) If the Work includes a "NOTICE" text file as part of its distribution,
then any Derivative Works that You distribute must include a readable copy of
the attribution notices contained within such NOTICE file, excluding those
notices that do not pertain to any part of the Derivative Works, in at least
one of the following places: within a NOTICE text file distributed as part of
the Derivative Works; within the Source form or documentation, if provided
along with the Derivative Works; or, within a display generated by the
Derivative Works, if and wherever such third-party notices normally appear.
The contents of the NOTICE file are for informational purposes only and do not
modify the License. You may add Your own attribution notices within Derivative
Works that You distribute, alongside or as an addendum to the NOTICE text from
the Work, provided that such additional attribution notices cannot be
construed as modifying the License.

You may add Your own copyright statement to Your modifications and may provide
additional or different license terms and conditions for use, reproduction,
or distribution of Your modifications, or for any such Derivative Works as a
whole, provided Your use, reproduction, and distribution of the Work otherwise
complies with the conditions stated in this License.

5. Submission of Contributions.

Unless You explicitly state otherwise, any Contribution intentionally
submitted for inclusion in the Work by You to the Licensor shall be under the
terms and conditions of this License, without any additional terms or
conditions. Notwithstanding the above, nothing herein shall supersede or
modify the terms of any separate license agreement you may have executed with
Licensor regarding such Contributions.

6. Trademarks.

This License does not grant permission to use the trade names, trademarks,
service marks, or product names of the Licensor, except as required for
reasonable and customary use in describing the origin of the Work and
reproducing the content of the NOTICE file.

7. Disclaimer of Warranty.

Unless required by applicable law or agreed to in writing, Licensor provides
the Work (and each Contributor provides its Contributions) on an "AS IS"
BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied, including, without limitation, any warranties or conditions of TITLE,
NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You
are solely responsible for determining the appropriateness of using or
redistributing the Work and assume any risks associated with Your exercise of
permissions under this License.

8. Limitation of Liability.

In no event and under no legal theory, whether in tort (including negligence),
contract, or otherwise, unless required by applicable law (such as deliberate
and grossly negligent acts) or agreed to in writing, shall any Contributor be
liable to You for damages, including any direct, indirect, special, incidental,
or consequential damages of any character arising as a result of this License
or out of the use or inability to use the Work (including but not limited to
damages for loss of goodwill, work stoppage, computer failure or malfunction,
or any and all other commercial damages or losses), even if such Contributor
has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability.

While redistributing the Work or Derivative Works thereof, You may choose to
offer, and charge a fee for, acceptance of support, warranty, indemnity, or
other liability obligations and/or rights consistent with this License.
However, in accepting such obligations, You may act only on Your own behalf
and on Your sole responsibility, not on behalf of any other Contributor, and
only if You agree to indemnify, defend, and hold each Contributor harmless for
any liability incurred by, or claims asserted against, such Contributor by
reason of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS


---

## Redistribution and Maintenance Notes

This notice is intended to accompany Talaria source distributions and to be
usable as an attribution source for applications that redistribute Talaria in
binary form.

Redistributors remain responsible for complying with the license terms
applicable to each third-party component. In particular:

- Do not remove upstream file-level copyright or license notices from
  third-party source files.
- If third-party source is copied or vendored into the Talaria repository,
  preserve its original license header and identify Talaria modifications
  where the upstream license requires modification notices.
- If an Apache-2.0 upstream distribution contains a `NOTICE` file applicable
  to material incorporated into Talaria, reproduce the relevant NOTICE
  attributions in a permitted location.
- When dependencies are upgraded, added, removed, replaced, vendored, or
  patched, update this file in the same change.
- For a binary release, generate or review a license inventory against the
  actual packages linked into that binary. `go.mod` is the authoritative
  starting point for this source release, but platform-specific build tags and
  vendored/copied source can change the final binary attribution set.
- The Go standard library and Go toolchain are outside the module list above.
  A distributor of compiled Go binaries should separately preserve any
  notices required for the Go runtime/toolchain portions actually included in
  its distribution.
