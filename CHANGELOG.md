# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A dotted key's last segment is looked for under the parent the key names.
  A file writes the whole key, as VS Code does, or nests it, as one putting
  `defaultMode` under `permissions` does, and placement looked for that
  segment anywhere: another block writing the same one is a different setting,
  and anchoring there put the finding on it.

- A server's name is placed at the key declaring it, in the block it was
  declared under. Placement looked for the name among the values of the block
  holding it, so a server named in a sibling's arguments came first in the
  file and `trusted-server` and `plaintext-transport` both pointed at that
  sibling's line instead. And a file may declare one name in two of the
  blocks clew reads, which are two declarations: each server now remembers
  the block it came from, so a finding about the trusted one does not quote
  its safe namesake. The five spellings live in one place for that, since a
  copy of a set that lives somewhere else is how the two come to disagree.

  A block's declarations are its own keys and not every key beneath them.
  Placement indexed all of them, so a server named like a property an
  earlier one holds, `command` or `url` among them, came first in the file
  and a finding about the trusted declaration quoted that property's line.
  What nests is now read the way the file writes it: brackets say it
  wherever a format has them, and indentation says it as well where that is
  what nests, which is YAML's block style. Indenting is read nowhere else,
  because a bracketed block laid out over lines of different widths declares
  all of them, and reading its indenting would keep only the one indented
  least.

  A key written inside a value is text rather than a declaration, which is
  the rule a value already followed. A server named like a word another
  server's value happens to hold was placed inside that value.

- A finding is no longer placed on a key written inside a comment. Placement
  finds a key by searching the text and took the first match, so a
  `# sandbox_mode = "danger-full-access"` left in a file as a note had
  `bypass-permissions` pointing at it and quoting the commented line as its
  evidence: a finding that reads as an accusation about a setting somebody had
  already turned off. Every rule placing by key had this.

  A key is now read left to right in one pass, because a key is only a key
  where the file is writing one. Inside a comment it is a note, and inside a
  value it is prose: a quoted one looks exactly like a key, and what tells
  them apart is the separator after the closing quote. Measured, a settings
  file naming the setting in a note had the finding land on the next thing
  that looked like the value, which was a different setting.

  What counts as a comment and as a string is now the file's format, which
  the rule placing a finding is given, because it is the one thing that cannot
  be decided without it: `//` opens a comment in JSONC and sits inside a url
  in YAML. So JSON has no comment to skip, JSONC ends a line at `//` wherever
  it appears and runs a block to `*/`, TOML ends one at a `#` wherever it sits
  while YAML and Bash need whitespace or a line start before it, since `a#b`
  is a scalar holding a hash in one and a word in the other, and TOML takes a
  single-quoted string literally and runs a long one between three quotes,
  honouring escapes in the basic form and none in the literal one, and closing
  on the last three of a run, since up to two quotes may sit against the
  delimiter and belong to the value. Bash also
  begins a token after an operator, so `:;# x` comments where `a#b` does not.
  A quoted key is read in either quote, since TOML and YAML both take one
  that way. A key written in any of those is text, not a declaration, and
  neither is a
  value: placement finds the key and then counts copies of the value after it,
  so a note between two declarations used to put the second finding on the
  note. The scan now carries through the values as well, and counts only the
  values a key was given, which is the list or block after it, the next entry
  where it sits inside one, or the rest of its line where it does not: a
  compact file writes a whole object on one line, and running to the newline
  there swallowed every key after this one, while outside a collection a comma
  separates nothing, which is how `allowed-tools: Bash(a), Read` gives one key
  two values, and the block indented beneath a key is that key's values too,
  which is how frontmatter writes a list of tools: a grant written that way
  used to fall back to naming the file rather than the line. So a `label` holding the same word between two `runOn` declarations
  is another key's value, and counting it put the second finding on the label.

  One pass also means a file holding many copies of a key costs its length
  rather than its square. Measured on a 760 KB file with twenty thousand
  commented copies: thirteen seconds of placement became half a second, which
  matters because the files a scanner reads are not ones it chose.

  That pass now runs once per file rather than once per declaration. Reading a
  file and placing a finding in it were separate walks: the reader found four
  thousand grants, and then each rule that reported one searched the file
  again for it, so the cost was the file's length times the number of things
  it declared. A mode was already read with its position, because the reader
  knew it; a grant, a task, a server and a hook command were not, and now
  they are. The reader builds one index of where a file writes the things it
  declares and the rule looks its subject up, which is the same answer in one
  walk. Measured on a file granting four thousand tools: 6.0 seconds became
  3.7, against 3.6 for the same file before placement began reading comments
  at all, so what is left of the difference is the cost of reading them.

  A key the file writes many times is one walk too. Taking the values of a
  key meant reading the file from its start, because what is a comment and
  what is a string is only known from there, and a file declaring two
  thousand automatic tasks writes `runOn` two thousand times: one walk each,
  which is the shape the index was built to remove, left in place for every
  key a file repeats. The walk is now separate from the range, so the values
  are collected once and each key takes the ones beginning inside its own.
  Measured on that file, 10.9 seconds became 9.1.

  What is left of that one is not placement. A finding quotes the line it
  sits on and masking a credential in that line costs the line's length, so
  a file written on one line pays for the whole file in every finding it
  earns. That is its own cost and this does not change it.

  Where a found thing ends is still the reader's to say and not the index's.
  A command written bare over several lines is indented in the file while the
  command is not, so nothing searching for its text can honestly bound it;
  only a reader that saw the block knows. A format read with positions gives
  that span and placement takes it as given rather than searching at all.

### Added

- Codex's named permissions profiles are read: `[permissions.<name>]` tables,
  what each grants and the parent each extends. A profile is a sandbox written
  apart from the key that selects it, so a mode naming one says nothing on its
  own about what the agent may reach.

- `unprompted-write-access`, the first rule that reads a whole scan rather
  than one thing in one file. It fires on a pair of Codex settings each of
  which clew calls harmless on its own: `approval_policy = "never"`, which
  stops the asking, together with a sandbox that permits writes, written
  either as `sandbox_mode = "workspace-write"` or as
  `default_permissions = ":workspace"`.

  The pair was already written down here as a limitation. `approval_policy`
  stays out of `bypass-permissions` because Codex still sandboxes, so an
  unasked agent is bounded; a sandbox permitting writes is bounded by
  something asking. Set both and neither bound is left, and what the agent
  may write unasked includes the files deciding what the next run does: a git
  hook, an instruction file, that configuration. `danger-full-access` is left
  to `bypass-permissions`, which reports it alone, so one key is not reported
  twice.

  A rule reading the whole scan belongs to no row, and a row's `check` list is
  what makes the catalogue the place behaviour is decided. So the catalogue
  names it, in `report_checks` beside `revision`, rather than every
  report-reading rule running ungated. Schema 4, because a reader that did not
  know the field would run none of the rules it names and report a clean scan,
  which is the half-reading this number exists to refuse.

  The finding is placed at the sandbox key, which is the half granting the
  writes, and its evidence names both halves rather than quoting that line:
  a reader shown `sandbox_mode = "workspace-write"` on its own, which this
  rule's own page calls harmless, would be right to think the finding wrong.

  The two halves need not be in one file. Codex walks up from the working
  directory until it reaches a project root, which its reference gives as a
  directory holding `.git`, then loads every `.codex/config.toml` from there
  down, and the closest file to the run wins a key, so a root that stops the
  asking and a nested file that permits writes leave neither control for a run
  below. That order is what makes a nested file putting the sandbox back the
  fix rather than another finding, and it is why the rule asks the question
  once for each directory a run could start under. The walk stopping at a
  project root is what keeps a submodule out of it: a submodule holds its own
  `.git`, so a run inside it never loads the superproject's configuration, and
  the scan notes where those markers are, `.hg` and `.sl` among them, although
  none is a surface and none is entered. A marker named only in
  `project_root_markers` is not read: that setting lives in a machine's own
  configuration outside any repository, which a scan of a repository never
  opens.

  A `.codex/config.toml` the scan could not read or understand stops the walk
  as well, and so does a `.codex` it could not list: either way the
  configuration there is unknown, and a pair joined across it would be a
  finding against settings no run ever had. Another tool's file failing to
  parse says nothing about these keys and does not stop it.

  A finding carries one path, so it is placed at the sandbox and the evidence
  names the file the other half came from, last, because evidence is clipped
  to a width and the two halves matter more than which file the far one sits
  in. Two pairs are compared before that clipping, so how wide a report quotes
  cannot change how many findings it holds.

  A `default_permissions` naming a `[permissions.<name>]` table of its own is
  resolved against that table rather than guessed at from its name. The
  reference gives a profile filesystem rules, which grant `"write"` at a path
  or under `:workspace_roots`, and an `extends` naming a parent applied before
  it, so the chain is walked: a profile granting nothing of its own still
  writes where its parent does. A file is free to write a cycle, and the
  answer there is no rather than a scan that does not finish.

  A profile extending `:danger-full-access` is read as the write it is. The
  reference does not list that built-in among the values `extends` takes, so a
  profile naming it names something undocumented; the two answers available
  are a finding on a configuration that may be unbounded and silence on one
  that is, and silence is the worse of them. It is also the one case
  `bypass-permissions` cannot see, because that rule reads the key selecting
  the profile, which says `ours` rather than its parent. Written out, that
  value is graded higher by that rule; behind a profile name it is graded here,
  which understates it by a grade and is better than saying nothing.

  The closest file wins a profile table as it wins any other key, so a root
  defining `ours` as read-only and a nested file redefining it as a write are
  two answers, and the nested one is in force below it.

  A directory holding only a profile is a run location too. A file defining
  the profile a file above it selects declares no mode of its own, and leaving
  it out of the candidate layers meant never asking about the one place that
  selection resolves to a write.

  A report indexes the declarations by the directory each sits in, once, and
  then walks a run's own directories rather than every declaration for each
  run. Measured on a chain four hundred deep holding eight thousand profiles:
  five point eight seconds became under one, and the cost is now bounded by
  how deep a repository nests rather than by how much it declares.

  Each mode is placed where its file wrote it as the scan reads that file, so
  the report carries a position rather than the text it came from. Holding the
  text instead would have kept every file declaring a mode open until the scan
  ended, which is as many megabytes as there are such files, and the only
  thing a report rule wanted from it was where to point.

  Naming a rule in the wrong one of the two lists is refused at load, both
  ways round. A row offers a rule the file it matched, so a row naming a
  rule that reads the whole scan runs nothing; `report_checks` offers nothing
  a file rule reads, so naming one there runs nothing either. Either mistake
  would otherwise be a rule listed, never run, and a clean scan.

- Codex's `default_permissions` is read, and `:danger-full-access` fires
  `bypass-permissions` as `sandbox_mode = "danger-full-access"` already did,
  which that rule's own page now says.
  The two are the same decision in two spellings, and reading one of them is
  how a configuration escapes a rule by being written the newer way.
  `approval_policy` is read as inventory, since a scan saying what a file
  declares cannot leave out the key deciding whether anyone is asked. Its
  table form is recorded by the name it holds, which the reference calls
  `granular`: a file writing it is overriding whatever a file above it said,
  and recording nothing for it left that other file's `never` standing as
  though nothing had replaced it. That key alone takes a table, so one found
  under any other mode is a shape nothing documents and is still passed over.

- Git hooks are read, which no row covered: `.git` is pruned by default, so
  `.git/hooks` was never entered, and clew did not see its own hooks in
  `.githooks` either. A hook runs on commit, on push and on merge without
  being asked and with whoever's credentials are at the keyboard, which is
  what an agent that commits triggers.

  Read from `.git/hooks`, `.githooks`, `.husky` and `hooks` at the repository
  root, by the twenty-nine names git's own documentation lists. By name rather
  than by wildcard for two reasons: git runs a hook by the name it looks for,
  so a file under any other name is not one, and `git init` fills `.git/hooks`
  with a sample per hook. Measured rather than assumed, those samples carry
  nothing any rule flags, so a wildcard would have cost a dozen surfaces in
  every repository ever initialised rather than a dozen findings. A count is
  what a prevalence figure is, so that is still a cost. Matching by name also
  keeps `hooks` usable as a row at all: it is where a React project keeps its
  own hooks.

  `.git/hooks` is reached by naming it on the row, which the scan seeds, and
  not by relaxing the prune. The one type whose whole job is what not to enter
  stays one rule rather than a rule with exceptions inside it. It is also the
  only one of the four git reads without being told to, so a scan that cannot
  enter it says so: a `.git` that is a link, which git follows and clew does not, is
  a gap rather than an absence. A directory that is simply not there stays an
  answer, as does the `.git` file a linked worktree carries, and so does a
  link at one of the other three, which hold candidate hooks rather than
  hooks git runs.

  Four holes, stated in the row, the README and here rather than left for
  someone to find. `core.hooksPath` is not read, so a repository pointing it
  somewhere else has hooks clew does not see; reading it means reading
  `.git/config`, which is INI and inside the pruned directory. A helper script
  a hook sources is not followed. A linked worktree and a submodule keep their
  hooks in the git directory their `.git` file points at, which is outside the
  tree being scanned and so not read. And a hook git ignores for not being
  executable is still reported, because the tree a scan reads exposes no file
  mode: these are candidate hooks rather than proven active ones, which
  inflates a count by whatever share is not executable.

  A surface reached twice is read once. A seeded directory can also be reached
  by walking, since a policy is free not to prune `.git`, and reading the same
  hook twice would have reported it twice and every finding in it twice.

  A seeded directory is read for the rows that named it and nothing else, one
  level deep. Putting it into the ordinary walk instead would have handed
  every row a subtree the prune list was told to skip, so a `CLAUDE.md` left
  in `.git/hooks` would have been read as an instruction file and a `.claude`
  directory there descended into.

  `seed` is validated as a plain path inside the scan root and recorded in the
  catalogue snapshot. It is the one field joined to that root and read rather
  than matched against something the walk already found, so a traversal
  segment in it would reach outside; and it changes which files a scan
  reaches, so the snapshot has to pin it or a later change could pass without
  the revision moving.

  A seed that is there and cannot be read is a gap, like every other
  directory this scan cannot open. Saying the scan was complete would mean
  reporting nothing found in hooks nobody looked at. Absent, and not a
  directory, stay answers: most repositories have no `.git/hooks`, and in a
  linked worktree or a submodule `.git` is a file.

  The catalogue schema is 3, not because a reader without `seed` would refuse
  the file but because it would parse the file and enter none of the
  directories the field names. That is the half reading the number exists to
  refuse.


- A corpus that pins what the rules decide, which neither version number
  could. `crates/bootstrap/tests/corpus/` holds a small repository per rule
  and `corpus.snapshot` holds the findings clew reports in each, so a rule
  whose logic changes fails there rather than passing quietly under the same
  pack version. Proven by breaking rules rather than by passing: making
  `unrestricted-shell` miss a bare `Bash`, `auto-run-task` miss `folderOpen`,
  or `plaintext-transport` match a loopback host as a prefix all fail the
  corpus, and so does a rule that starts firing where its prose promises
  silence.

  Ten of the twenty-four fixtures are silent on purpose, each a case some
  rule's own text names: the `grep` pattern that quotes `curl | sh` without
  running one, the download that reaches `tar` rather than an interpreter,
  `npx` running what the project already installed, an MCP server on
  loopback, a shell grant with its commands written out, a task waiting to be
  chosen, an agent in CI that was not told to stop asking.

  A fixture is a manifest rather than a directory of real files. clew scans
  its own repository in CI, and a tree of deliberate findings would fail that
  run, so each fixture is written to a temporary directory and scanned there.
  Nothing a fixture lays out is platform-dependent: `opaque-hook` is a file of
  invalid UTF-8 rather than a symbolic link, because a link cannot be made the
  same way everywhere and a fixture that lays out differently on one operating
  system records a snapshot that agrees with itself and nothing else.
  The test calls the library rather than the binary, because
  `check-no-exec.sh` reads every Rust file in the repository and a test that
  spawned a process would break the guarantee it checks.

- `--format jsonl`, one document per tree read, each on its own line, which is
  the shape a run over many repositories appends to. The same writer over the
  same types as `--format json`, so a line and a one-scan document cannot
  drift apart. Every line repeats the version numbers, because a line read on
  its own has to say what judged it, and every line is a record: nothing else
  is written, so appending run after run leaves a file a reader can take a
  line at a time. `rules` and `explain` refuse it as they refuse
  `--format sarif`, since neither is a scan and accepting an option to then
  write something else is the silent kind of wrong.

- GitHub Actions workflows are read, which no row covered. A workflow is
  configuration that runs code with nobody at the keyboard, in a job holding
  its token and whatever secrets it was given; which events trigger it and
  which secrets it receives are not read, so neither is claimed. Each `run:`
  step is judged as the shell it is, so the five rules that already read a
  hook's command read a CI step too: a `curl | sh` in a workflow is
  `download-and-execute` without a new rule, and `credential-exfiltration`
  already knows what a token looks like. `invisible-unicode` reads the file
  as text rather than as commands, which is a sixth rule by a different path.

  `agent-runs-unattended`, severity high, flags a step that runs an agent CLI
  with the flag waiving every permission prompt. Each flag was read from that
  tool's own reference or its argument definitions: Claude Code's
  `--dangerously-skip-permissions` and `--permission-mode bypassPermissions`,
  Codex's `--dangerously-bypass-approvals-and-sandbox`, and Gemini CLI's
  `--yolo`, `-y` and `--approval-mode yolo`.

  The near misses are deliberately absent, which is most of what reading the
  references bought. Claude Code's `--allow-dangerously-skip-permissions` adds
  the bypass mode to the mode cycle without starting in it, so an unattended
  run never reaches it. Codex's `--ask-for-approval never` on its own leaves
  the sandbox at its read-only default, which is the same line
  `bypass-permissions` already draws; only the flag that waives the sandbox
  too is listed, and Codex's source confirms it sets both. Gemini CLI's
  `--approval-mode auto_edit` auto-approves edit tools alone. `dontAsk` is not
  listed because the reference names it without saying what it does.

  A flag belongs to the tool that defines it. Reading them as one set would
  have `-y`, which is `yes` to most of the world, waive a prompt Claude Code
  never offered, and would fire on `npx -y` answering npx rather than the
  agent it goes on to run. The rule reads the parsed commands rather than the
  text, so `echo claude --dangerously-skip-permissions` runs no agent and a
  lint forbidding the flag is not itself a finding. A word the file does not
  hold, such as `$FLAGS`, is not read as a flag.

  The row is anchored at the repository root rather than `**/`, because that
  is the only place GitHub loads a workflow from. A nested `.github/workflows`
  is a fixture, a vendored copy or another project's tree, and a
  high-severity finding there would be about a file nothing executes.

  Only a POSIX shell is read as one. A workflow may run PowerShell, Python or
  a shell of its own choosing, and a Windows runner defaults to PowerShell, so
  the effective shell is resolved from the step, the nearest
  `defaults.run.shell` and the runner, and a step that is not Bash or sh is
  reported and left unjudged. Judging one language by another's syntax answers
  a question nobody asked.

  A package runner is read by the form it runs things in, not by its name.
  `npm view @openai/codex` and `pnpm add @google/gemini-cli` name a package
  without running it, so only `npx`, `bunx`, `uvx`, `npm exec`, `pnpm dlx`,
  `pnpm exec`, `yarn dlx`, `bun x` and `deno run` count, and within those the
  option values and the `--` separator are read before the program, since
  `npx --package @google/gemini-cli -- echo` runs `echo`. A wrapper is read
  through, so `env FOO=1 claude --flag` and `sudo -u ci gemini --yolo` are
  found; a runner handed a wrapper that then runs the agent is knowingly
  missed, which the rule says.

  `--` ends a command's own options, so `claude -- --dangerously-skip-\
  permissions` passes that text as an argument and waives nothing.

  A runner has to say which operating system it is. `runs-on: ubuntu-latest`
  and the `group`/`labels` mapping both do; `self-hosted`, a label a project
  invented, and a job with no `runs-on` at all do not, and a job without one
  is a job GitHub refuses to run. An expression is resolved through the matrix
  it names, where every key the label refers to has to resolve and every value
  the deciding key can take has to be POSIX, since a run picks one of them. A
  step whose shell stays unknown is reported and left unjudged, which loses a
  finding on a job clew cannot place rather than reading one language as
  another.

- YAML is read with the position of every value it holds, through the
  parser's own events rather than the high-level loader, which gives a tree
  with no positions in it. A finding in a workflow is placed where the file
  wrote the command instead of by searching the text for it again, which went
  wrong wherever the same text appeared twice: a command repeated in a
  comment or a step name above the step that runs it, two jobs opening on the
  same line, two steps running the same thing. The span bounds the search as
  well as starting it, so a line inside a folded block cannot be found in a
  later step.

  The reader resolves merge keys, which the loader does not. A job written
  `<<: *base` inherited no steps, so its commands were in the file and clew
  said nothing about any of them. Anchors and aliases keep working as they
  did, and a test now pins that, since the code reads as though it drops them.

- `Format::Yaml`, which the workflow rows need and which nothing else uses
  yet. It is deliberately not folded in with JSON the way JSONC is: no tool
  writes a mode or a grant in YAML, and folding it in would have clew report a
  mode out of a workflow that happened to carry the key path. A CI workflow
  has a `permissions:` block of its own, which means something else entirely.

- Crush is read, which it was not at all. Five rows cover both forms it loads:
  `crushrc`, which is Bash that runs with the user's shell privileges before
  the UI appears, and the deprecated `crush.json`, which is still discovered
  and still merged. Crush's own documentation calls both trusted code, so
  `crushrc` carries a hook script's seven checks rather than a parsed row's,
  and `CRUSH.md` joins the instruction files read for hidden characters. Each
  row matches the dotted and undotted name under one glob, because Crush loads
  either.

  Four of its shapes differ from every tool already catalogued, and each was
  invisible before this. Its hooks put the command on the entry rather than
  under an inner `hooks` array, so a `curl | sh` registered in a Crush hook
  read as nothing. Its grants are `permissions.allowed_tools`, sharing the
  block Claude Code names `allow`. Its servers are under `mcp`, a fifth
  spelling, which left `plaintext-transport` silent on every Crush file. And a
  `crushrc` carries neither a shell extension nor a `#!` line, being sourced
  rather than executed, so nothing but its name says the one Crush file that is
  entirely commands is shell at all.

  `unrestricted-shell` now reads Crush's lowercase `bash`. The cost is stated
  in the rule's own text: a lowercase entry in a Claude Code allow list grants
  nothing there and is still reported, which is the right answer for a shell
  grant that was meant to work. No row reads an autonomy value from Crush,
  because its `permissions` block admits a grant list alone and the flag that
  waives every prompt is passed on the command line, which no file records.

  A `crushrc` is the only row read twice: as the Bash it is, and for what its
  builtins declare. That form configures Crush by calling them, so
  `hook add --command`, `permissions allow` and `mcp add --url` declare as
  commands the same things the JSON form declares as data. The new `crushrc`
  format reads those calls into the shape Crush's own loader files them under,
  so every extractor reads a `crushrc` without a case for it, and a hook
  registered there is followed to its script exactly as a JSON one is.

  Only what a scan can know is recorded. `permissions allow $(cat list)` has
  no answer until the file runs, so a tool or server name carrying a
  substitution is left out rather than reported under a name nothing is
  called; a substitution is kept whole while splitting it, or the tail of
  `$(cat extra list)` would be read as a tool of its own. A command string is
  kept as written, since `curl $URL | sh` is worth reporting whether or not
  `$URL` is known. `permissions deny` hides a tool rather than pre-approving
  one and is not read as a grant. Crush compares a whole argument against each
  flag name, so `--command=x` is an unknown flag to it and is not read as one
  here.

  A finding in a `crushrc` is anchored to the call that causes it, because a
  builtin separates a name from its values with spaces, which the key anchor
  does not accept and must not: a bare word followed by a space is most of
  English. Without that, every `crushrc` finding would point at the file rather
  than at a line.

  Crush's own `defaultContextPaths` carries six spellings of its context file,
  and a glob matches the case a file has on disk, so all six are named. It also
  auto-loads `.config/crush/CRUSH.md` and `.config/AGENTS.md` from outside any
  repository, which now have home rows.

  A global Crush config is read from `.config/crush`, the default for
  `$XDG_CONFIG_HOME/crush`. A machine that moves that variable keeps its global
  Crush config out of a home scan's reach, as it does for every other
  variable-rooted path.

### Changed

- `CONTRIBUTING.md` said pinning a rule's decisions "would take a corpus of
  fixtures with their findings recorded, which clew does not have yet". It has
  one now, and the section says what the corpus does and does not cover rather
  than claiming more than it should.

### Fixed

- A scratch directory in three test helpers was named by the process id
  alone. Process ids are reused, so a run inheriting an earlier run's
  leftovers laid one test's tree over another's, and the removal meant to
  prevent that discards its error. Found by writing a test that collided with
  one from a week earlier: this machine held leftovers from 360 distinct
  process ids.

  Each is now created rather than cleared, and removed when the test ends.
  `create_dir` fails when the name is taken, so a leftover is stepped over
  instead of written into. A counter was the first attempt and was not enough:
  it restarts at zero in every process, so the same names come round again
  with the same process id. Stepping over a name only works while names are
  left, so the directory is a guard that clears itself rather than another
  entry in a pile that was already 2,500 deep. A full run adds none now.


- A command written bare rather than as a JSON string yielded its finding
  about the file rather than at the line, since placement looked only for the
  quoted form a settings file writes. Every finding in a YAML `run:` block
  would have been a path and nothing else to go on.

- Two jobs were read in the order their names sort rather than the order the
  file writes them, because a parsed map was key-sorted. Occurrences were
  counted in one order and placed by searching in the other, so each job's
  finding landed in the other's block, carrying one job's evidence and the
  other's line number. YAML is now read with the position of every value, so
  nothing is placed by counting.

- A finding was placed on any line holding the waiver's flag, whether or not
  that line ran an agent, so `echo --dangerously-skip-permissions` above a
  real invocation took the finding. The same reading that finds it now
  chooses where it goes.

- Two steps whose blocks open on the same line were both placed in the first
  of them, because the copy was counted on the whole block while placement
  looks for the line it opens with. Counted on the same text now.

- A step was redacted before the rules read it, which suppressed findings
  rather than producing wrong ones. Masking `TOKEN=$(gh auth token)` to
  `TOKEN=**** auth token)` destroys where the token came from, so the
  exfiltration below it went unreported: the same command in a hook was a
  `credential-exfiltration` finding and in a workflow was nothing. A step is
  now judged as the workflow wrote it and redacted on its way into the report,
  which is what a hook's command already did. A custom `shell:` is redacted
  too, being a command line a token can be written into.

- Two agent invocations in one block both pointed at the first, because the
  line holding the flag was looked for from the start of the file rather than
  from the block, and without an ordinal. Each is now looked for inside its
  own block, counted per flag so two commands waiving by different ones are
  told apart.

- A pre-approval under a key absent from the placement list yielded its finding
  about the file rather than at the line, quietly, since the finding still
  appeared. Both placement lists are now counted by a test, so a spelling added
  to one without the other fails rather than degrading.

## [0.8.0] - 2026-10-04

### Added

- `plaintext-transport` flags a remote MCP server declared with an `http`
  endpoint, so the session that carries the agent's arguments, the results it
  reads back and whatever header authenticates it crosses the network in the
  clear. Fourteen catalogue rows across nine tools run it, the broadest reach
  any one rule has. Silent on `https`, on a server launched locally, and on an
  endpoint that stays on the machine, which is what keeps it quiet on Gemini
  CLI's own documented `http://localhost:8080` example. Loopback is decided by
  parsing the host rather than matching a prefix, so
  `127.0.0.1.example.invalid` is still a finding.

  The first rule whose backing is a specification rather than an incident: the
  MCP Streamable HTTP transport requires a server to validate `Origin`, asks it
  to bind loopback rather than every interface, and says it should authenticate
  every connection. The specification never requires TLS, so the rule says this
  is a weakness in how a server is deployed rather than a breach of the
  protocol.

- `auto-run-task` flags a task whose `runOptions.runOn` is `folderOpen`, which
  VS Code runs when the containing folder is opened. Opening a repository is
  what a reviewer does before reading any of it, so the command runs before
  anyone has looked at what it is, and a task naming no command of its own
  still runs the ones it depends on. CVE-2026-10591 is where this led: AWS
  fixed Kiro IDE 0.11 because its file write tool let crafted instructions
  write this trigger. The rule's own text carries the two limits rather than
  discounting them from its grade, that an automatic task never runs in an
  untrusted workspace and that `task.allowAutomaticTasks` defaults to prompting
  once.

- `**/.vscode/tasks.json` is read for the tasks it declares, each reported with
  what it runs and when, including a compound task that names only
  `dependsOn`. A task's command is masked as it is read, since a deploy task is
  a routine place for a token.

- `**/.vscode/mcp.json` is read for the servers it declares. The row had been
  inventory only, and filling it in alone would still have found none of them:
  VS Code spells the table `servers`, keeping `mcpServers` for the portable
  `.mcp.json`.

- A server declared with `httpUrl`, which Gemini CLI documents for streamable
  HTTP, is reported. Such a server names no command, so it used to be discarded
  rather than reported, and `trusted-server` never saw the ones that declared
  `trust`. A scan that lists nothing reads as a clean result.

### Changed

- The `core` pack is at version 3 and the catalogue at revision 4.

### Fixed

- A server declaring both `url` and `httpUrl` is reported at the endpoint a
  tool actually connects to. Gemini CLI takes `httpUrl` first and logs that it
  is ignoring `url`, so naming the other pointed a reader at a host nothing
  reaches.

- A url is read the way the client that fetches it will read it. The URL
  Standard strips leading controls and spaces, removes every tab and newline
  anywhere in the input, and reads a backslash as a slash for a special scheme,
  all before parsing, so a value written with a tab inside its scheme is
  fetched as plain `http`. Six of seven such forms went unreported, two of them
  because redaction could find no scheme and withheld the url entirely.

### Security

- No report carries a credential a scanned file holds. A hook's event, type and
  command, a grant's tool and scope, a mode's key and value, and a server's
  name, executable, endpoint path and environment keys were all reported as
  written, so a token inline in a hook command was printed in full by the text
  output and carried verbatim in the JSON one. Each is redacted as it enters the
  report, after the rules have read what the file wrote, so a finding still
  lands where the declaration sits and the files a hook names are still
  followed.

- A scanned file cannot write a line of a report. Every name, path and command
  the text output prints is read out of a file under review, and none was
  escaped, so a newline in a declared value split the output and the forged half
  read as a line clew had written. A server named
  `evil\n  server "trustworthy": https://safe` rendered as two entries, the
  second naming a server nothing declared. `json` and `sarif` were never
  affected, since both escape a control character on the way out.

## [0.7.0] - 2026-09-30

### Added

- Rules belong to a named pack with a version of its own, so a set can be added
  without renumbering the rules already there and one pack can change without
  invalidating a run that cited another. One pack ships, `core`. The pack's
  `rules` list is where a rule is registered, and a rule in no pack, or in two,
  fails a test rather than being quietly not run.

- Every report names the packs that judged, rather than one number: a scan's
  JSON carries `packs` where it carried `rule_pack`, the SARIF driver carries
  `rulePacks`, `clew --version` names each pack, and a rule in `clew rules` or
  `clew explain` carries the pack and version that judged it. One number would
  have had a second pack's findings citing the first pack's version.

- Each rule is one file under `crates/domain/src/rules/`, holding its id,
  severity, wording, what it reads and what it finds. The eight matches that
  used to spread one rule across the crate are gone, replaced by a single arm in
  `rule::of` that the compiler still checks.

- A rule is a value clew holds rather than a name threaded through every match
  that wanted to know about it. `clew_domain::rule::Rule` says what a rule reads
  and what it says about one thing, `shipped` is the registry, and one dispatcher
  replaces the six entry points a scan used to call. Adding a rule meant editing
  nine places across seven matches; the compiler caught an omission, and a test
  comparing the registry against the rule pack now does. The six functions that
  judge are reachable only through the registry, so a rule cannot run without
  being one.

- `clew rules` lists every rule clew applies, and `clew explain RULE` says what
  one means, what to do about a finding under it, and where it is written up.
  Both take `--format json`, and each document names the rule pack, so a study
  can record what judged. Neither takes `--fail-on` or `--format sarif`: both
  belong to a scan, and a flag that promises to change the exit status is
  refused rather than accepted and dropped. An id that names no rule is refused
  with the ids that exist rather than resolved to the one it nearly named.

- A page per rule under `docs/rules/`, and a SARIF `helpUri` pointing at it, so
  a code scanning alert leads somewhere. The pages and the README's rule table
  are generated from the rule pack by `./scripts/rule-pages.sh`, and CI fails if
  they drift: the same words reach an alert, a terminal and a page, and four
  copies of a sentence is how one rule comes to mean three things. A page no
  rule claims, left by a rule removed or renamed, is reported too.

- A version per rule pack and a catalogue revision, so a finding can be cited
  and traced to the rules that made it. Each names the set of rules and rows,
  not the logic inside a rule: rewording a rule or re-dating a row leaves both
  alone, so two runs stay comparable when nothing about the set changed. A
  snapshot test compares each against the code, and `check-revisions.sh`
  compares it against the base, which is the only way to see a snapshot updated
  alongside its content without the number moving.

- The catalogue declares schema 2, and a file declaring another is refused
  rather than half read. `revision` became required when it was added, which is
  a change of shape, and the schema version had been parsed and ignored since it
  was introduced.

- `RuleId::all`, `RuleId::detail` and `RuleId::remediation` on `clew-domain`.
  What a rule means and what to do about it were written into the SARIF
  adapter, where the only way to read them was to generate a log; they sit
  beside the model now, so a log, a command and a page can say the same words.
  `all` is what lets the rule set be listed at all, which nothing could do
  before.

## [0.6.0] - 2026-09-24

### Added

- The `bypass-permissions` rule, severity high. It flags a configuration file
  that starts an agent with nothing asking first and nothing bounding what
  happens: Claude Code's `permissions.defaultMode` set to `bypassPermissions`,
  Codex's `sandbox_mode` set to `danger-full-access`, VS Code's
  `chat.tools.global.autoApprove` set to `true`, or Zed's
  `agent.tool_permissions.default` set to `allow`. Only those four fire. Codex
  `approval_policy = "never"` does not, because Codex still sandboxes, to
  `read-only` by default; the other three sandbox nothing, so there the prompt
  was the only control. Claude Code stopped honouring `bypassPermissions` from
  project and local settings in v2.1.257, so a repository setting it reaches
  only an older client, and Zed's built-in security rules still prompt for a
  few actions.

- `.vscode/settings.json` is read, for the switch that auto-approves every tool.
  It was not in the catalogue at all, so nothing in a VS Code workspace was.

- The `unrestricted-shell` rule, severity medium. It flags a configuration file
  or a skill that pre-approves the shell with nothing restricting what it runs:
  Claude Code's `Bash` or Gemini CLI's `run_shell_command`, bare or at `*`, in
  `permissions.allow`, `tools.allowed`, or a skill's `allowed-tools`. Every
  command the agent picks then runs without being shown to anyone. Only the
  shell is flagged: a bare `WebSearch` or `mcp__server__tool` is unscoped too,
  but neither takes an argument restriction, so a bare entry is the only way to
  write that grant. Scoped entries are silent, and so are the `deny` and `ask`
  lists, which clew does not read as grants. One file granting the same
  operation twice gives a finding at each entry.

- The `trusted-server` rule, severity medium. It flags an MCP server declared
  with `trust: true`, which Gemini CLI documents as bypassing all tool call
  confirmations for that server. A server decides for itself what tools it
  offers, so a tool added after the trust was granted is trusted too, and a tool
  whose description changes is never shown again. Only a boolean is the switch,
  so the string `"true"` is not, and `trust` is Gemini's spelling: the same key
  in a file read by a tool that ignores it is reported as part of the
  declaration rather than flagged. The finding is placed at the name the server
  is declared under.

- The mode a settings file starts an agent in is reported beside the hooks,
  permissions and servers it declares, whether or not a rule objects to it. It
  is the first thing clew reads out of a settings file that is not a grant.

## [0.5.0] - 2026-09-17

### Added

- A script a hook runs is read as a hook script wherever it sits in the
  repository. Only files under a `hooks` directory were read, so
  `bash scripts/check.sh` or `"$CLAUDE_PROJECT_DIR"/tools/hook.py` ran code no
  rule saw. What runs comes from the command's shell syntax, parsed with
  tree-sitter and never executed: a path in command position, or the file
  handed to an interpreter such as `bash`, `python3`, `node` or `uv run`, never
  a file a command only reads or writes. A path that might leave the checkout,
  absolute, under `~`, through another variable or `..`, is never followed,
  and only a repository scan follows at all: anywhere else a relative path
  belongs to whichever project the agent was started in.

- The `download-and-execute` rule, severity high. It flags a hook script, or a
  hook command in a settings file, that hands what it downloads straight to a
  shell or an interpreter: `curl ... | bash`, `wget -qO- ... | sh`,
  `curl ... | sudo python3`, `bash <(curl ...)`, `eval "$(curl ...)"`, a
  `bash -c` line doing the same, and PowerShell's `irm ... | iex`. It reads
  shell syntax, never words, so a guard whose `grep` pattern names `curl | sh`
  is silent, a download that goes only to `tar` or `jq` is silent, and a hook
  file is read as commands only when its name or its `#!` line makes it a
  shell script.

- The `decode-and-execute` rule, severity high. It flags a hook that hands
  what it decodes straight to an interpreter: `base64 -d`, `base32 -d`,
  `openssl ... -d`, `xxd -r`, or a decompressor writing to standard output,
  piped into a shell, run through `eval "$(...)"`, `sh -c "$(...)"` or
  `bash <(...)`, or in a `bash -c` line, as the xz-utils backdoor's
  `... | xz -d | /bin/bash` was. PowerShell's `-EncodedCommand`, a `-Command`
  line handing `FromBase64String` to `iex`, and a `python3 -c`, `node -e` or
  `php -r` line that both decodes and runs are flagged too. Decoded text that
  nothing runs is silent, and so are `eval "$(ssh-agent -s)"` and
  `-ExecutionPolicy`.

- The `credential-exfiltration` rule, severity high. It flags a hook that sends
  a credential over the network: the environment (`env`, `printenv`), a token
  a tool prints (`gh auth token`, `gcloud auth print-access-token`), a
  credential file (`~/.aws/credentials`, `~/.npmrc`, a private SSH key, a
  `.env` sent whole), what a cloud metadata service answers, or a variable
  assigned one of these. It is followed into what `curl`, `wget` or `nc`
  sends: piped or redirected in, named as a file with `@` or `-T`, or
  substituted into the payload or the address. A token in a header or user
  that authenticates the request is silent, as is anything sent to localhost,
  a public key, and configuration read out of `.env`.

- The `unverified-download` rule, severity medium. It flags a hook that
  downloads a file and later runs it, or unpacks it and later runs something
  from where it unpacked it, with no checksum or signature checked in between:
  `curl -o f && ./f`, `curl -O a.tgz; tar xf a.tgz; ./a/bin/a`, and
  `curl ... | tar -xz -C d; d/bin/tool`. A variable may hold anything the script
  assigned it earlier, so a download named through one is still followed. A
  `sha256sum -c`, `shasum -c`, `gpg --verify`, `cosign verify-blob`,
  `minisign -V` or `gpgv` silences it, and a tool run by name is taken to be
  the one on `PATH`.

- The `unpinned-remote-package` rule, severity low. It flags a hook that runs a
  registry package at a tag that moves, `latest`, `next`, `canary`, `beta` and
  the like, through `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `uvx` or
  `pipx run`: whatever was published last runs, each time the hook fires.
  Without a version a runner takes what the project installed, and with one it
  takes that version, so neither is flagged. The rules that read commands now
  look through `xargs`, whose `-I {}` and other valued flags are skipped.

### Fixed

- A hook written in exec form, with an `args` list, is reported with its
  arguments. Only `command` was read, so a script named in `args`, or the
  payload handed to `bash -c`, never reached the report. The arguments are
  quoted into one line that splits back into them.

## [0.4.0] - 2026-09-14

### Added

- A GitHub Action, `Sysogen/clew`, that scans the checkout and uploads the
  SARIF log to code scanning. It installs the clew release it names for the
  runner, refusing one that does not match its published checksum, prints the
  report to the job log and the run's summary page, passes `fail-on` through,
  and ends the step as clew exits, after the upload.

- A SARIF log tags each rule it lists `security` and gives it a
  `security-severity` score in GitHub's band for the rule's severity, so code
  scanning shows its findings as security alerts ranked high or medium, as
  clew ranks them.

## [0.3.0] - 2026-09-13

### Added

- `--fail-on low|medium|high` on `path` and `system`: exit `2` when a finding
  is at that severity or worse. Without it a finding still does not change the
  exit status, and an incomplete scan still exits `1`, even beside a finding,
  since what it could not read may hold more.

### Fixed

- Piping the text report into a reader that stops early, such as
  `clew path . | head`, no longer panics when the pipe closes. The scan finishes
  and exits with its usual status.

- A release waits for CI to finish on its commit rather than failing because
  it has not. `Tag` starts the release as soon as a version change lands, while
  CI on that commit is still running, which stopped the first 0.2.0 attempt.

## [0.2.0] - 2026-09-13

### Added

- `--format sarif` on `path`: a SARIF 2.1.0 log for code scanning. A finding at
  a place is a result at its line and column, and one about a whole file names
  the file. Severities high, medium and low are `error`, `warning` and `note`,
  and a scan that could not read everything reports
  `executionSuccessful: false` with a notification for each path. `system`
  refuses it: SARIF places a result by its path in a repository, and neither
  tree `system` reads is one.

- `--format json` on `path` and `system`: the whole report as one JSON document
  under `"version": 1`, with an entry in `scans` for each tree read. Any control
  or default-ignorable character, variation selectors included, is written as a
  `\u` escape, so the document decodes to exactly what was found without
  carrying the character itself.

- Read hook scripts. A bidirectional character in code is Trojan Source
  (CVE-2021-42574): the script reads one way to a reviewer and runs another,
  so `invisible-unicode` now reads them. A hook that is not text, is larger
  than the file limit, or is a link that clew will not follow is an
  `opaque-hook` finding, severity medium, rather than a gap in the scan: what
  it runs cannot be reviewed. A hook that clew was not allowed to open is
  still a gap.

- Findings. A rule says something is wrong, where a row only says what a file
  declares. Findings sit on the report beside surfaces, sorted by path and
  position, and a finding does not make a scan incomplete: it is a scan that
  worked and found something.

- The `invisible-unicode` rule, severity high. It flags zero-width,
  bidirectional, tag-block and other non-printing characters in instruction,
  rules and skill files: the Rules File Backdoor, disclosed by Pillar Security
  on 18 March 2025. Non-printing means Unicode's Default_Ignorable_Code_Point,
  so blank fillers such as U+3164 are caught and visible format marks such as
  the Arabic number signs are not. A catalogue row names the rules that read
  it with `check`, so settings a tool keeps beside its rules are never quoted.
  A run of hidden characters is one finding, so a smuggled instruction does
  not fill the report. A byte order mark opening a file is left alone, as are
  variation selectors and non-breaking spaces. The evidence escapes the
  character as `<U+XXXX>` so a report never carries the payload, and quotes at
  most `CLEW_EVIDENCE_WIDTH` characters of the line, never fewer than 12.

- Recognise a secret by its shape with the default rules of betterleaks,
  gitleaks' successor by the same author, vendored unedited under its MIT
  licence. Each rule's Expr filter runs, token efficiency included, so a
  placeholder or a readable word is not taken for a secret. A rule's
  `validate` is never run: it would send the credential to its issuer.

- `clew system` also reads the rules an administrator deploys to the machine,
  `/etc/devin/rules` and the legacy `/etc/windsurf/rules`. Nobody being scanned
  chose those, and they are in neither tree that engineer owns.

- `clew system`, which scans the home directory for the agent configuration
  kept outside any repository: user-level MCP servers, global rules, and
  global skills for Claude Code, Gemini CLI, Kiro, Windsurf, Zed, and Cline.
  A repository holds what a team shares and reviews; this is the half nobody
  reviews. The scan enters only the directories those rows name rather than
  walking a home directory, and a root that is absent means the tool is not
  installed rather than a gap in the scan.

- Catalogue rows carry a `scope`: `repository`, `home` or `system`. Each tree
  is matched separately, so a path two trees both use is never reported
  against the wrong one.

- Find `.env` and `.env.*`, reported and never opened: the file is credential
  values, and clew records none. `.envrc` is a direnv script and not matched.

- Find Cline rules in `.clinerules`, and the `GEMINI.md` and `AGENT.md`
  instruction files. The shared names are matched last, so a rules directory
  holding one keeps its own row.

- Find Zed project settings, skills, and `.rules`. Its MCP servers sit under
  `context_servers`, so that key is read alongside the two common spellings.
  Zed writes JSON with `//` comments, so that row is read as `jsonc`.

- Find Windsurf rules: `.devin/rules`, the legacy `.windsurf/rules`, and the
  legacy `.windsurfrules`. Its MCP configuration lives outside a repository,
  so it is read by `clew system`.

- Read Kiro agent hooks, which list entries naming their own trigger rather
  than keying a map by event. Both shapes are read from the same key.
  An injected prompt is reported alongside a shell command, since both fire
  unasked, and a hook switched off is reported as switched off rather than
  hidden. The report says which: `runs on`, `injects on`, and `(disabled)`.

- Find Kiro surfaces: its workspace MCP configuration, reported with the
  servers it declares, plus steering files. A steering file setting
  `inclusion: always` enters every interaction.

- Find Gemini CLI project settings and report the MCP servers they declare.

- Find `.vscode/tasks.json`. A task can set `runOn: folderOpen`, which runs it
  when the folder is opened. Reported, never opened.

- Find Cursor project rules under `.cursor/rules`, `.mdc` files only, since
  Cursor ignores a plain `.md` there.

- Read Markdown frontmatter, so a skill reports the tools it is allowed to use.
  The opening fence must be the first line, as the tools themselves require, and
  a fence that never closes is an error rather than an empty result.

- Read TOML, so Codex `config.toml` reports the MCP servers it declares. Every
  format parses into the same value, so every extractor works on any of them.

- CI proves clew cannot execute what it finds: a source scan for any
  process-spawning API on every build, and a symbol scan of the Linux and macOS
  release binaries for any process-spawning import.

### Changed

- A `*` in a catalogue glob now stays inside one path segment. It crossed `/`
  before, so `.env.*` also took a directory named `.env.local`, and a row had
  no way to say "one directory deep".

### Fixed

- Report a named directory whose link points nowhere as a gap rather than as a
  tool that is not installed. Something put the link there.

- Never walk into a directory reached by a symbolic link found while walking.
  A directory clew was told to read is read even when it is a link: `/etc` is
  one on macOS, and a dotfile manager commonly makes `~/.claude` one. The check
  followed the link, so a home root such as `~/.claude -> /elsewhere` was
  traversed and reported files outside the tree being scanned. The root the
  operator names is still followed; everything discovered below it is not.

- Stop redacting the argument after a value that merely reads like a
  credential. `docker run -e JIRA_API_TOKEN ghcr.io/org/image` hid the image,
  which is what a typosquat check reads. Only a flag introduces a value.

- Five catalogue citations pointed at pages that had moved or gone. Every
  source now resolves and names the file its row claims, and `.cursorrules`
  cites the page saying it is legacy, which is why the row stays.

### Security

- Mask credential values in the evidence a finding quotes. A token beside a
  hidden character in an instruction file was quoted whole. A value is masked
  when set against a credential key (`API_KEY=`, `password = `, `password:`,
  `"api_key":`, a `?token=` query), after a credential flag, after `Bearer` or
  `Basic`, or when one of betterleaks' rules knows its shape; a quoted value is
  masked whole. The line is masked before any rule can quote it, so a secret
  cut at the edge of the quoted window is still masked.

- Never record a credential written into an MCP argument or url. A value behind
  a flag naming a credential, one written as `key=value`, and one whose shape a
  betterleaks rule knows are replaced by `<redacted>`; a url keeps its host and
  path and drops its userinfo and query. Only the names of environment
  variables were held back before, so a token passed as `--api-key` reached the
  report. The value is dropped as the file is read, so nothing downstream holds
  one.

## [0.1.0] - 2026-09-11

The first release cut from the public repository.

### Added

- Release automation: a version bump on `main` tags itself, then publishes the
  workspace to crates.io and attaches binaries for five targets.

- Report the MCP servers a configuration declares, with how each is reached
  and the names of the environment variables it is given. Names only: a value
  there is routinely a credential.
- Report the operations a Claude Code settings file pre-approves, summarised
  per file, naming any grant that covers a whole tool rather than one use.
- Recognise hook scripts and skill definitions: anything in a `hooks`
  directory under `.claude`, including the `.claude/skills/<name>/hooks`
  layout, and `.claude/skills/<name>/SKILL.md`.
- Report the hooks a Claude Code settings file registers, under the file that
  registers them.
- Report directories that could not be read, and exit non-zero when a scan was
  incomplete. Previously an unreadable directory was skipped in silence, so a
  permission-denied scan printed a clean result.
- `--version` and `--help`, and a `path` subcommand naming what the tool does.

### Changed

- Catalogue rows declare what to extract. A row without `extract` is inventory:
  reported, never opened. Adding a tool is now a data change.
- Cursor and Cline MCP files are parsed for the servers they declare, which they
  were not before.
- A file is parsed once however many extractions its row declares, rather than
  once per extraction.
- Surface patterns move from Rust into `crates/domain/catalogue.toml`, one row
  each, carrying the tool, the kind, the date it was last checked and the
  documentation it was checked against.
- The library crates change shape ahead of their first publication. Only
  `clew-cli` 0.0.0 has been released and it carried no library API, so nothing
  downstream can break:
  - `clew_domain::classify` is removed. `clew_domain::catalogue().lookup` now
    returns a `Matched` carrying the row, the kind and the extractions, rather
    than a tuple.
  - `clew_domain::tools` is removed with it. `CodingTool`, `ClaudeCode` and
    `REGISTRY` have no replacement: a tool is a catalogue row now.
  - `ParseError` moves from `clew_domain::tools` to `clew_domain::extract`.

- Restructure into five crates along ports and adapters: `clew-domain`,
  `clew-application`, `clew-adapter-cli`, `clew-adapter-fs`, and `clew-cli` as
  the composition root. The compiler enforces the dependency direction, and the
  traversal is tested against an in-memory tree rather than a temporary
  directory.
- Move to edition 2024 and resolver 3, pinned to Rust 1.98.1, with the declared
  minimum verified in CI.
- Reject an unknown subcommand instead of falling through to a default.

### Security

- Never follow a symbolic link. A link is reported and not traversed, so a scan
  cannot be walked out of its own root.

## [0.0.0] - 2026-09-10

Published to crates.io before this repository was public. The tree it was built
from is not in this history and no `v0.0.0` tag exists, so 0.1.0 is the first
tagged release.

### Added

- `clew path [DIR]` reports recognised AI coding agent configuration surfaces:
  MCP server definitions, hook configuration, and instruction files across
  Claude Code, Codex, Cursor, VS Code, Continue, Cline, Aider, Copilot, and
  devcontainers.
- `CLEW_MAX_DEPTH` sets the directory recursion limit.

[Unreleased]: https://github.com/sysogen/clew/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/sysogen/clew/releases/tag/v0.8.0
[0.7.0]: https://github.com/sysogen/clew/releases/tag/v0.7.0
[0.6.0]: https://github.com/sysogen/clew/releases/tag/v0.6.0
[0.5.0]: https://github.com/sysogen/clew/releases/tag/v0.5.0
[0.4.0]: https://github.com/sysogen/clew/releases/tag/v0.4.0
[0.3.0]: https://github.com/sysogen/clew/releases/tag/v0.3.0
[0.2.0]: https://github.com/sysogen/clew/releases/tag/v0.2.0
[0.1.0]: https://github.com/sysogen/clew/releases/tag/v0.1.0
[0.0.0]: https://crates.io/crates/clew-cli/0.0.0
