# Changelog

Every release of Filetrace, newest first. A version reads year.month.patch.build.

## 26.11.7.4 (2026-11-12)

### Bug Fix

- Forget a script id in the kernel when its name loses its slot ([7c5104c](https://github.com/OrlovEvgeny/filetrace/commit/7c5104cae02747372271ab55f78320d04e724353))
- Open PHP libraries as mapped and probe each real file once ([80a2668](https://github.com/OrlovEvgeny/filetrace/commit/80a26683f7e77b679935ec1ff0e77ae0048db117))
- Log the path and process of each probed PHP binary ([1eb91c6](https://github.com/OrlovEvgeny/filetrace/commit/1eb91c6c9f7408195ba67dd6495f0129f5ed3967))

## 26.11.6.5 (2026-11-12)

### New Feature

- Name the script of each PHP request from probes on PHP ([6f12780](https://github.com/OrlovEvgeny/filetrace/commit/6f12780ad3497ecefbda3be8c270136ba79f4b83))

## 26.11.5.6 (2026-11-11)

### New Feature

- Report a PID namespace other than the host's in doctor ([b69be3f](https://github.com/OrlovEvgeny/filetrace/commit/b69be3f6739f276ba0a411f7ef5cc7732a574d1c))

### Bug Fix

- Take the command line and directory from the exec record ([5dd7e0b](https://github.com/OrlovEvgeny/filetrace/commit/5dd7e0b9de14ab6fe58406a4ce1a82420d901571))
- Skip /proc reads outside the host PID namespace ([310560c](https://github.com/OrlovEvgeny/filetrace/commit/310560cb60f6eb7e21cd79d2f5ff4486464dea2f))

## 26.11.4.16 (2026-11-11)

### New Feature

- Derive the script an interpreter runs from its arguments ([d750911](https://github.com/OrlovEvgeny/filetrace/commit/d750911942930edad4c33e03dba9e8f9b0da324c))
- Keep the command line, directory and script of each process ([56f20aa](https://github.com/OrlovEvgeny/filetrace/commit/56f20aab94f77e20a4cb7f8c34e325d028740b86))
- Show command line, directory and script in listings ([e9b53f8](https://github.com/OrlovEvgeny/filetrace/commit/e9b53f869ac47d5b1bfd39629c53c30dc1ba1909))
- Filter processes, transfers and events by script ([8ab3862](https://github.com/OrlovEvgeny/filetrace/commit/8ab38624b22c8da216bf00b87ab4a59685d9cb11))
- Export what a process runs in OTLP log records ([606ffd4](https://github.com/OrlovEvgeny/filetrace/commit/606ffd4370f126f7fa5967ec96b3f1a15703f9b9))
- Serve the command line, directory and script over gRPC ([cce3858](https://github.com/OrlovEvgeny/filetrace/commit/cce3858b8dbe1211399557a11556b07aaf376068))
- Add settings that keep process arguments out ([2bfa362](https://github.com/OrlovEvgeny/filetrace/commit/2bfa36272dd3b4afa2fb0ab906fb7be9f3f4b3f7))

## 26.11.3.4 (2026-11-11)

### Bug Fix

- Keep reads of background files from taking over a send ([758c198](https://github.com/OrlovEvgeny/filetrace/commit/758c19892e25d705bdf76a1cf9f7a9bd7ab11a42))
- Learn background files from the paths the kernel reports ([36fed69](https://github.com/OrlovEvgeny/filetrace/commit/36fed69255ee5e5d9d46ff3b6024c18cb58d66c5))

## 26.11.2.11 (2026-11-11)

### New Feature

- Report files in no_minimum_paths below the inferred minimums ([eebbfc6](https://github.com/OrlovEvgeny/filetrace/commit/eebbfc6ebdc51f46d51673651f7d5d729b59a6bb))

### Bug Fix

- Send only the exact installer and key paths to the bucket ([ba947c3](https://github.com/OrlovEvgeny/filetrace/commit/ba947c3fef7560829fc5ec141c495a4a17a3f213))
- Answer a failed precondition by the body R2 leaves undefined ([aa35b66](https://github.com/OrlovEvgeny/filetrace/commit/aa35b66e4033d799b90bd0272f22f026fe7c5b89))
- Install the libraries the agent links to in the vm image ([21248e3](https://github.com/OrlovEvgeny/filetrace/commit/21248e327ae4e833c1d165fab86a566dd939527c))
- Let a receive end the file claim of the kprobe set ([78e461a](https://github.com/OrlovEvgeny/filetrace/commit/78e461a08bbd85ec604c49e8e16e147a5d96bfee))
- Refuse a channel without a release before configuring a repository ([9142f85](https://github.com/OrlovEvgeny/filetrace/commit/9142f85a95a611b38a976fc47034d01834ce3bf9))
- Let a receive on any socket end the file claim of the kprobe set ([3cba2b8](https://github.com/OrlovEvgeny/filetrace/commit/3cba2b898f461c51e05dcf6b11c5207d7f550309))
- Check a channel where the chosen install method reads it ([43e5839](https://github.com/OrlovEvgeny/filetrace/commit/43e583932cd47cef06a55e546e615608ce72c63d))

## 26.11.1.160 (2026-11-11)

### New Feature

- Add core data model and bounded tables ([9a70918](https://github.com/OrlovEvgeny/filetrace/commit/9a70918734a0bad85f1fbf03fa3b445f0e2e4037))
- Add observation state and queries ([7130fd4](https://github.com/OrlovEvgeny/filetrace/commit/7130fd431e97d64567f18bc714e7d56dbb983d3e))
- Add ipc client ([e9cdb16](https://github.com/OrlovEvgeny/filetrace/commit/e9cdb163ce0fbc7e0858597530f54ac85ff368c9))
- Add collection backend interface ([45fd255](https://github.com/OrlovEvgeny/filetrace/commit/45fd2556fe8ef80a3386a6ffc9c0d7358b5db52d))
- Add linux ebpf probes ([b353d8e](https://github.com/OrlovEvgeny/filetrace/commit/b353d8e9858e42795ccb82e3db36748365c18f80))
- Add linux ebpf loader and diagnostics ([61e2dc6](https://github.com/OrlovEvgeny/filetrace/commit/61e2dc616a8ecd03309e9ad13e478c5f858efba1))
- Add daemon with local query socket ([5aa3aba](https://github.com/OrlovEvgeny/filetrace/commit/5aa3aba0f9b78f0a34d709923c65aa14f63c720a))
- Add command-line interface ([b4c57e7](https://github.com/OrlovEvgeny/filetrace/commit/b4c57e7edb85b2927f5f2816ef6ca0531bc370cd))
- Trace through kprobes on kernels without bpf trampolines ([3094b53](https://github.com/OrlovEvgeny/filetrace/commit/3094b532c4e921425816279da936d6254a40c5cc))
- Record file size, file owner and network namespace ([1d40e1c](https://github.com/OrlovEvgeny/filetrace/commit/1d40e1c05ca95a8ae4b86de0aa294fdc2f3beea1))
- Report byte rates per process, socket, flow and transfer ([8bd638d](https://github.com/OrlovEvgeny/filetrace/commit/8bd638d3ca1f97a0a324a1b77cd2ac937b172c26))
- Match remote and local addresses by network prefix ([ba1f5e2](https://github.com/OrlovEvgeny/filetrace/commit/ba1f5e29b0b3ecfa25222efa690d93283d8ecd84))
- Filter files by path regex and by file size ([637e89c](https://github.com/OrlovEvgeny/filetrace/commit/637e89cb640a58a10854fa63f8e6fe79e3981090))
- Sort by duration, process name and file path ([cf2096f](https://github.com/OrlovEvgeny/filetrace/commit/cf2096f07eef0e36ce778af5133a7d7ea5af8fde))
- Add json and jsonl shorthand flags ([6e3beaa](https://github.com/OrlovEvgeny/filetrace/commit/6e3beaaf04b56f1e4e9b2f106f77c17a5543a179))
- Give flows stable ids and query by socket or flow ([9be93d9](https://github.com/OrlovEvgeny/filetrace/commit/9be93d9548630af95380463e035a91c2d6673b0f))
- Count distinct files and active transfers per process ([30a3427](https://github.com/OrlovEvgeny/filetrace/commit/30a342796cb4c851ce4eb8e9bab0091f07a81cd5))
- Name transfer methods as the cli contract does ([68f5ce8](https://github.com/OrlovEvgeny/filetrace/commit/68f5ce873fad662b118a438cd40dd6923e257db4))
- Name output fields as the cli contract does ([feb1a29](https://github.com/OrlovEvgeny/filetrace/commit/feb1a2983fb2ae51d3ee1003604a157c284c4e34))
- Lay out list tables as the cli contract shows them ([8ea9def](https://github.com/OrlovEvgeny/filetrace/commit/8ea9def99ec54f86f77a181917e1ef66fd3cfac5))
- Keep a bounded log of events and add the events command ([803862f](https://github.com/OrlovEvgeny/filetrace/commit/803862f57dea5045ce8f32dbc0b469ded98d57e5))
- Add inspect for files, processes, sockets, flows and addresses ([61a1599](https://github.com/OrlovEvgeny/filetrace/commit/61a1599b879dfd054aabce56631549d3104d8b5c))
- Filter sockets, flows and transfers by user, cgroup and namespace ([689c15e](https://github.com/OrlovEvgeny/filetrace/commit/689c15ef2eb31f32f427f987be719bc5d6679ad5))
- Rebuild watch with file, process and network views ([1a0ad7c](https://github.com/OrlovEvgeny/filetrace/commit/1a0ad7cbc0c72f0f1295c1890106022c43878835))
- Let the collector ignore protocols, processes and paths ([440ec6b](https://github.com/OrlovEvgeny/filetrace/commit/440ec6bdc7e459fb1d044e8bba2443015f38d3a8))
- Let the backend skip the read and sendfile probes ([c0ab1a2](https://github.com/OrlovEvgeny/filetrace/commit/c0ab1a2065909a3003fdaadba227b4090117fc7f))
- Read settings from a configuration file ([1912867](https://github.com/OrlovEvgeny/filetrace/commit/19128678aee573f10064b255e237b8dfcc5a265b))
- Report system facts, probes, features and pipeline in doctor ([42ee6df](https://github.com/OrlovEvgeny/filetrace/commit/42ee6df83a8a388c725bbaff70c8825d10e0d7b2))
- Show agent status and the main commands for a bare filetrace ([009a63f](https://github.com/OrlovEvgeny/filetrace/commit/009a63f987224daa7f6a973a99211ab7ab516c55))
- Show remote addresses by host name on request ([436c8aa](https://github.com/OrlovEvgeny/filetrace/commit/436c8aad84aafff4082a5f09964493bc1dd8cea2))
- Count sent bytes and transfers per process for export ([1dec552](https://github.com/OrlovEvgeny/filetrace/commit/1dec55289ac51e77e7563a227c08c2286bce3801))
- Serve metrics to prometheus ([1730ae2](https://github.com/OrlovEvgeny/filetrace/commit/1730ae221bd94645b555499b37902cb4bac4a191))
- Add a grpc client and server over nghttp2 ([f5b9bb6](https://github.com/OrlovEvgeny/filetrace/commit/f5b9bb6f4e8f8195ee2626cbc5575fddd37c38af))
- Export events and metrics over otlp ([b0da574](https://github.com/OrlovEvgeny/filetrace/commit/b0da5741030dd5eeda6d2d87604795efc73962d4))
- Define the grpc api in protobuf ([23a3b23](https://github.com/OrlovEvgeny/filetrace/commit/23a3b23800ff35d359ce69bd92b4fcd7d73fbf88))
- Serve status and transfers over grpc ([c2d2636](https://github.com/OrlovEvgeny/filetrace/commit/c2d2636d749d049f91a1785ff64159bb988c0b6e))
- Derive the release version from git tags ([91d4e2c](https://github.com/OrlovEvgeny/filetrace/commit/91d4e2c89fd379e33be1b411c66dac15e2307c52))
- Report the version derived from git tags ([b8fe3d5](https://github.com/OrlovEvgeny/filetrace/commit/b8fe3d52c2d53121843a115664169ffb815e4dde))
- Print the commit in filetrace version ([c5c5def](https://github.com/OrlovEvgeny/filetrace/commit/c5c5def516d78353f4a0a1dc3f87054e45f931d1))
- Add --version to filetrace-agent ([332aeae](https://github.com/OrlovEvgeny/filetrace/commit/332aeaeb3dba87e9c1560c11d9dbbc9f883e0509))
- Add an option to link third-party libraries statically ([3c98b1e](https://github.com/OrlovEvgeny/filetrace/commit/3c98b1e7ba24ccc9634fc1c3edab899f2b5dbef0))
- Add a default configuration file for packages ([6d9479d](https://github.com/OrlovEvgeny/filetrace/commit/6d9479d9bd9388ef3ecdcd508bb17c05733ae30f))
- Add service definitions for systemd, openrc and sysv init ([d228de9](https://github.com/OrlovEvgeny/filetrace/commit/d228de9402eb4a2530f4ce3c301b3d243f52c4b9))
- Add maintainer scripts shared by deb, rpm and apk ([a4a001d](https://github.com/OrlovEvgeny/filetrace/commit/a4a001d0fa64595b2b571121a41ab81174d8d06f))
- Build tarballs and deb, rpm and apk packages ([808a80e](https://github.com/OrlovEvgeny/filetrace/commit/808a80e7823e91ad19c456b0037d13074254047f))
- Add an installer script ([283d022](https://github.com/OrlovEvgeny/filetrace/commit/283d022e733ba9f4401393fa321beecb0191802c))
- Build macos release binaries ([3f0b3a7](https://github.com/OrlovEvgeny/filetrace/commit/3f0b3a7943f341f742aa3f5c77582f502e896fff))
- Sign the rpm and apk packages when keys are given ([c573b87](https://github.com/OrlovEvgeny/filetrace/commit/c573b8770159c276c9aacd018f9546b488d030b7))
- Build signed apt, yum and apk repositories ([2e70496](https://github.com/OrlovEvgeny/filetrace/commit/2e70496315dee28842931af05fa6046d52a261f0))
- Let apt fetch the repository indexes by checksum ([6345da2](https://github.com/OrlovEvgeny/filetrace/commit/6345da2edd1dec09a85e804f8dc6fbdde12ee2b1))
- Serve the files of every release from the download site ([2a79de5](https://github.com/OrlovEvgeny/filetrace/commit/2a79de5f0587e9838c6f9225a0d0f3f3d36c7697))
- Add a script that uploads the download site to r2 ([a4f4ae2](https://github.com/OrlovEvgeny/filetrace/commit/a4f4ae2a44deb3d000b556abd5ce4e2640298b4c))
- Point the installer at filetrace.eorlov.org ([e271c3b](https://github.com/OrlovEvgeny/filetrace/commit/e271c3bcbcc0ff4a90d7c12e626eb84be0d94a17))
- Print a keg-only homebrew formula for a release line ([b270b9b](https://github.com/OrlovEvgeny/filetrace/commit/b270b9b5550fdbdcb52980d556025317a3cf2bc0))
- Write the formula of the line to the tap on every release ([79f1625](https://github.com/OrlovEvgeny/filetrace/commit/79f16255fcb56e8d9a9d0063b86b3bcb1bee8a97))
- Serve the docs and the downloads through one worker ([da6ec93](https://github.com/OrlovEvgeny/filetrace/commit/da6ec93bc70a832c4fd41ec0dcefb596b3694edd))

### Performance Improvement

- Skip draining counter maps that received no entries ([21f2168](https://github.com/OrlovEvgeny/filetrace/commit/21f21687490e53aa2b14208a9c636e2570c79c0a))
- Use a smaller event queue in minimal mode ([cfd462b](https://github.com/OrlovEvgeny/filetrace/commit/cfd462b51835cfb59e1ad6408ffe208638f9d916))

### Bug Fix

- Omit processes without traffic from ranked views ([3234f9f](https://github.com/OrlovEvgeny/filetrace/commit/3234f9f1a5729749c33e2f8c856ccf2539a13444))
- Tell apart files that reuse a deleted inode number ([766f92b](https://github.com/OrlovEvgeny/filetrace/commit/766f92b08c40c0e84ad47a102d34f813ddf97cbd))
- Keep a foreground collector from serving metrics ([7d3a905](https://github.com/OrlovEvgeny/filetrace/commit/7d3a9052e485a65f747bf351df777e50465fb81a))
- Reconnect at once after an idle grpc connection closes ([7f6086a](https://github.com/OrlovEvgeny/filetrace/commit/7f6086a8aa13e95a07bdbd9c3e38650aa30e59e4))
- Widen the version field of the stats row ([36312dd](https://github.com/OrlovEvgeny/filetrace/commit/36312ddb1b5e0a9e8ee7f3d680449955abd3a44f))
- Set file modes explicitly in the release archives ([e79579d](https://github.com/OrlovEvgeny/filetrace/commit/e79579d55dbdd77737e10e92b52326b37bb89827))
- Make the installer upgrade from its own repository ([ffa6d1d](https://github.com/OrlovEvgeny/filetrace/commit/ffa6d1d40dccee8e343de8c5a0f66f6b3a091ad5))
- Deploy the download site when its build succeeded ([b85fc6e](https://github.com/OrlovEvgeny/filetrace/commit/b85fc6e1ca69ce86440b999ecfaed0ff4fca6206))
- Name the x86 registers as the kernel does in the kprobe programs ([2bf4201](https://github.com/OrlovEvgeny/filetrace/commit/2bf4201a675960e0f8c27d857682e736eefd84b3))
- Let the publish job run again after the release is public ([e0ea133](https://github.com/OrlovEvgeny/filetrace/commit/e0ea133551fffc72ed01caa1ee19ce948b898777))
- Fail the homebrew formula when an archive has no checksum ([077383b](https://github.com/OrlovEvgeny/filetrace/commit/077383b215250f325eddd9a27b210f9a5abeae78))
- Write the homebrew formulae once the site serves their files ([331f253](https://github.com/OrlovEvgeny/filetrace/commit/331f253d8aac24b88c37a78cf77839786b3e49e9))
- Stop the site step when the published release is not listed yet ([22dbf75](https://github.com/OrlovEvgeny/filetrace/commit/22dbf756c1d35f37e6c565d0919155c18de4d3c6))
- Make the help texts name what the commands accept ([8944f6d](https://github.com/OrlovEvgeny/filetrace/commit/8944f6d1b4678a01e48fc9e9cedf7e909d686d92))
- Print the byte count note after the last option in top and events ([7a22887](https://github.com/OrlovEvgeny/filetrace/commit/7a228872e230a45e42ca68da7b6c20dc6360c999))
- Label the capabilities fallback when the socket is not accessible ([32f7e40](https://github.com/OrlovEvgeny/filetrace/commit/32f7e4058fe1ce9b55fc311fc4a99ea198440374))
- Drop the unlisted --include-path option of files and transfers ([ecd12ff](https://github.com/OrlovEvgeny/filetrace/commit/ecd12ff317f6f939feb0d8069289ccb871576094))
- Say that collection needs linux in the macos caveat ([efd1043](https://github.com/OrlovEvgeny/filetrace/commit/efd1043d8bd90b3f980c83f71cc48099c0497674))
- Refuse exporter addresses the agent cannot use when validating ([5e4b842](https://github.com/OrlovEvgeny/filetrace/commit/5e4b842cda19139e1c36c8cfeb890d7a7f630662))
- Stop the agent cleanly on a hangup ([a0462ba](https://github.com/OrlovEvgeny/filetrace/commit/a0462bac06484c35f3dba207f33036de2ca569ed))
- Point the sitemap and llms.txt at filetrace.eorlov.org ([311ef6f](https://github.com/OrlovEvgeny/filetrace/commit/311ef6f1cc80e48f28d4b3be344e758a58d2fb30))
- Name the option that does not apply instead of calling it unknown ([bff3aef](https://github.com/OrlovEvgeny/filetrace/commit/bff3aef33632f56e2f24f623096248fb558ac706))
