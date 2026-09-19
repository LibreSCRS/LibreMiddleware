#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""workflow-step-order.py -- a step cannot run where it was placed.

Two failures this repository has already shipped, neither of which any existing
check could see:

  * a step whose `working-directory:` names a tree that the checkout creating it
    has not run yet, and
  * a gate step sitting in a job that does not run on push, so the gate is
    wired, bounded, green -- and never executed.

The wiring check sees the name, the timeout check sees the bound, and both stay
green in either case.

WHAT THIS JUDGES, AND WHAT IT DELIBERATELY DOES NOT
---------------------------------------------------
Only what GitHub Actions declares as data: `working-directory:`, `uses:`, `if:`,
`needs:`, `strategy.matrix`, `defaults.run.working-directory`. It does NOT
interpret the body of a `run:` script beyond a short list of recognised
directory-creating forms. A relative path inside a shell command cannot be
resolved without executing it, and guessing with a regular expression produces a
false failure on the first `git clone` inside a `run:` -- which this repository
has. Threat model: an honest mistake in moving a step, and a job that does not
run -- yes. Deliberate concealment -- no.

Two known doors, written down rather than pretended away:

  * a step that DELETES a tree (`rm -rf X`) does not remove X from the provided
    set, so a reader after it stays green. That is not today's failure class.
  * an absolute path is not judged at all: whether /tmp/x exists is not a
    property of step order.

Exit codes -- a consumer writes the condition as `rc == 0`, never "not 1":

  0  every reader is after the checkout that provides its tree, and every gate
     step is provably reached on push (or carries a recorded reason)
  1  one of those is false; every finding is printed with workflow, job and step
  2  cannot judge: no workflows, fewer than ci/workflow-shape.txt declares, a
     job with no steps, no gate step found in a repository that ships gate
     scripts, unreadable YAML, or PyYAML missing. Refusing to judge is never a
     pass.

Usage:
  ci/scripts/workflow-step-order.py            judge .github/workflows/*
  ci/scripts/workflow-step-order.py FILE...    judge only these files
"""

import os
import re
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - measured as exit 2, never as a pass
    sys.stderr.write(
        "FATAL: PyYAML is not importable -- this check reads the workflows as "
        "data and cannot judge without it\n")
    raise SystemExit(2)

# A step is a "gate step" when its `run:` body names a path that looks like one
# of this project's own scripts. Shape, not existence: the committed fixture
# below describes another repository's workflow, and this check is byte-identical
# in every repository, so a rule that asked the filesystem would judge a
# different set in each one and the self-test could not be shared.
GATE_PATH_RE = re.compile(
    r"(?:^|[\s\"'(=|&;]|\./)"
    r"((?:ci|tools|packaging|scripts|Scripts|e2e)/[A-Za-z0-9._/-]+\.(?:sh|py))")

# `if:` expressions that say "this always runs". Anything else is either a
# matrix reference, which is modelled, or a reason that has to be recorded.
ALWAYS_IF = ("always()", "success()", "true", "!cancelled()")

MATRIX_IF_RE = re.compile(
    r"^matrix\.([A-Za-z_][A-Za-z0-9_-]*)"
    r"(?:\s*==\s*'([^']*)'|\s*==\s*\"([^\"]*)\")?$")

CLONE_DIR_RE = (
    re.compile(r"\bgit\s+clone\b[^\n;&|]*?\s(?!-)(\S+)\s*$", re.M),
    re.compile(r"\bgh\s+repo\s+clone\b[^\n;&|]*?\s(?!-)(\S+)\s*$", re.M),
    re.compile(r"\bmkdir\s+(?:-p\s+)?([^\n;&|]+)", re.M),
    re.compile(r"\btar\b[^\n;&|]*?\s-C\s+(\S+)", re.M),
)


class Cannot(Exception):
    """Raised for every "I cannot judge this" condition; becomes exit 2."""


def tracked(pathspec):
    """Files git tracks under pathspec, or [] when this is not a checkout."""
    try:
        out = subprocess.run(["git", "ls-files", "--", pathspec],
                             capture_output=True, text=True, check=False)
    except OSError:
        return []
    if out.returncode != 0:
        return []
    return [line for line in out.stdout.splitlines() if line]


def on_section(doc):
    """`on:` is a YAML 1.1 boolean, so safe_load gives the key as True."""
    for key in ("on", True, "True"):
        if isinstance(doc, dict) and key in doc:
            return doc[key]
    return None


def triggers(doc):
    section = on_section(doc)
    if section is None:
        return set()
    if isinstance(section, str):
        return {section}
    if isinstance(section, list):
        return {str(item) for item in section}
    if isinstance(section, dict):
        return {str(key) for key in section}
    return set()


def clean_if(expr):
    """Strip the ${{ }} wrapper, if any, and surrounding space."""
    text = str(expr).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return text


def matrix_values(job, key):
    """Every value `key` takes across the job's matrix, include legs included."""
    strategy = job.get("strategy") or {}
    matrix = strategy.get("matrix") or {}
    if not isinstance(matrix, dict):
        return []
    values = []
    axis = matrix.get(key)
    if isinstance(axis, list):
        values.extend(axis)
    elif axis is not None:
        values.append(axis)
    for leg in matrix.get("include") or []:
        if isinstance(leg, dict) and key in leg:
            values.append(leg[key])
    return values


def truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip() not in ("", "false", "0")


def step_runs_on_push(job, step):
    """(bool, why) for a step's own `if:`."""
    if "if" not in step:
        return True, ""
    expr = clean_if(step["if"])
    if expr in ALWAYS_IF:
        return True, ""
    hit = MATRIX_IF_RE.match(expr)
    if hit:
        key = hit.group(1)
        wanted = hit.group(2) if hit.group(2) is not None else hit.group(3)
        values = matrix_values(job, key)
        if not values:
            return False, "matrix.%s is not in this job's matrix" % key
        if wanted is None:
            if any(truthy(value) for value in values):
                return True, ""
            return False, "no matrix leg gives %s a truthy value" % key
        if any(str(value) == wanted for value in values):
            return True, ""
        return False, "no matrix leg gives %s the value '%s'" % (key, wanted)
    return False, "if: %s" % expr


def job_runs_on_push(name, jobs, has_push, seen=None):
    """(bool, why) for a job, following `needs:` transitively."""
    if not has_push:
        return False, "the workflow has no push trigger"
    seen = seen or set()
    if name in seen:
        return False, "needs: forms a cycle through %s" % name
    seen = seen | {name}
    job = jobs.get(name)
    if job is None:
        return False, "needs: names a job that does not exist (%s)" % name
    if "if" in job:
        expr = clean_if(job["if"])
        if expr not in ALWAYS_IF:
            return False, "if: %s" % expr
    needs = job.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    for parent in needs:
        ok, why = job_runs_on_push(str(parent), jobs, has_push, seen)
        if not ok:
            return False, "needs: %s, which %s" % (parent, why)
    return True, ""


def provided_by(step):
    """Directories this step creates, relative ones only."""
    made = []
    uses = str(step.get("uses") or "")
    if re.match(r"^actions/checkout@", uses):
        with_ = step.get("with") or {}
        made.append(str(with_.get("path") or "."))
    body = step.get("run")
    if isinstance(body, str):
        for pattern in CLONE_DIR_RE:
            for hit in pattern.finditer(body):
                for token in str(hit.group(1)).split():
                    made.append(token)
    out = []
    for path in made:
        path = path.strip().strip("'\"")
        if not path or path.startswith("$") or os.path.isabs(path):
            continue
        out.append(os.path.normpath(path))
    return out


def reads_tree(step, defaults_wd):
    """The relative directory this step needs, or None."""
    wd = step.get("working-directory")
    if wd is None and "run" in step:
        wd = defaults_wd
    if wd is not None:
        wd = str(wd).strip().strip("'\"")
        if wd and not wd.startswith("$") and not os.path.isabs(wd):
            return os.path.normpath(wd)
    uses = str(step.get("uses") or "")
    if uses.startswith("./"):
        return "."
    return None


def covers(provided, wanted):
    """Is `wanted` inside something already provided?"""
    if wanted in (".", ""):
        return "." in provided
    for have in provided:
        if have == ".":
            return True
        if wanted == have or wanted.startswith(have + "/"):
            return True
    return False


def defaults_wd_of(doc, job):
    for holder in (job, doc):
        run = ((holder.get("defaults") or {}).get("run") or {})
        if "working-directory" in run:
            return str(run["working-directory"])
    return None


def gate_scripts_in(step):
    body = step.get("run")
    if not isinstance(body, str):
        return []
    return sorted({hit.group(1) for hit in GATE_PATH_RE.finditer(body)})


def step_label(index, step):
    name = step.get("name") or step.get("uses") or "run"
    return "#%d %s" % (index, str(name).splitlines()[0][:60])


def read_exceptions(path):
    """{(workflow, job, step-or-None): reason}, plus the raw rows for staleness."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            text = line.split("#", 1)[0].strip() if line.lstrip().startswith("#") else line.rstrip("\n")
            if not text.strip() or text.lstrip().startswith("#"):
                continue
            parts = re.split(r"\s{2,}|\t", text.strip(), maxsplit=1)
            key = parts[0]
            reason = parts[1].strip() if len(parts) > 1 else ""
            bits = key.split(":")
            if len(bits) == 2:
                rows.append((lineno, bits[0], bits[1], None, reason))
            elif len(bits) == 3 and bits[2].isdigit():
                rows.append((lineno, bits[0], bits[1], int(bits[2]), reason))
            else:
                rows.append((lineno, key, None, None, reason))
    return rows


def read_shape(path):
    shape = {}
    if not os.path.exists(path):
        return shape
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            bits = line.split()
            if len(bits) == 2 and bits[1].isdigit():
                shape[bits[0]] = int(bits[1])
    return shape


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            doc = yaml.safe_load(handle)
    except OSError as exc:
        raise Cannot("cannot read %s: %s" % (path, exc))
    except yaml.YAMLError as exc:
        raise Cannot("%s is not loadable YAML: %s" % (path, exc))
    if not isinstance(doc, dict):
        raise Cannot("%s does not parse to a mapping" % path)
    return doc


def judge(paths, exceptions, shape, repo_mode):
    findings = []
    used_rows = set()
    gate_steps_seen = 0
    jobs_total = 0

    for path in paths:
        doc = load(path)
        wf = os.path.basename(path)
        jobs = doc.get("jobs") or {}
        if not isinstance(jobs, dict) or not jobs:
            raise Cannot("%s declares no jobs" % path)
        has_push = "push" in triggers(doc)
        jobs_total += len(jobs)

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                raise Cannot("%s: job %s is not a mapping" % (path, job_name))
            steps = job.get("steps")
            if steps is None and "uses" in job:
                continue                    # a reusable-workflow call has no steps
            if not steps:
                raise Cannot("%s: job %s has no steps" % (path, job_name))
            job_ok, job_why = job_runs_on_push(str(job_name), jobs, has_push)
            defaults_wd = defaults_wd_of(doc, job)

            provided = set()
            for index, step in enumerate(steps, 1):
                if not isinstance(step, dict):
                    raise Cannot("%s: %s step %d is not a mapping"
                                 % (path, job_name, index))

                scripts = gate_scripts_in(step)

                # A step that runs one of this project's own scripts reads the
                # checkout by definition: the path it names is in the tree. That
                # is not interpreting the run: body for arbitrary relative paths
                # -- it is the same path-shape signal the gate-step rule below
                # already computes. It is what catches a gate step placed in a
                # job that has no checkout at all, which the deploy job of a
                # pages workflow is: one step, no checkout, and the gate would
                # read a tree that does not exist.
                wanted = reads_tree(step, defaults_wd)
                if wanted is not None and not covers(provided, wanted):
                    findings.append(
                        "%s::%s step %s reads '%s' before anything provides it "
                        "(provided so far: %s)"
                        % (wf, job_name, step_label(index, step), wanted,
                           sorted(provided) or "nothing"))
                elif scripts and not provided:
                    # A step that runs one of this project's own scripts needs a
                    # checkout to have happened in this job -- the path it names
                    # is in the tree. WHICH directory it ends up in is not
                    # guessed: a `cd` inside the run: body is exactly the thing
                    # this check does not interpret, and one job here does that.
                    # "Some checkout, anywhere" is the weakest claim that still
                    # catches the shape that matters: a gate step in a job with
                    # no checkout at all, which the deploy job of a pages
                    # workflow is -- one step, no checkout, and the gate would
                    # read a tree that does not exist.
                    findings.append(
                        "%s::%s step %s runs %s in a job that never checks "
                        "anything out"
                        % (wf, job_name, step_label(index, step),
                           ", ".join(scripts)))

                for made in provided_by(step):
                    provided.add(made)

                if not scripts:
                    continue
                gate_steps_seen += 1
                step_ok, step_why = step_runs_on_push(job, step)
                if job_ok and step_ok:
                    continue
                why = job_why if not job_ok else step_why
                row = None
                for candidate in exceptions:
                    _, c_wf, c_job, c_step, _ = candidate
                    if c_wf == wf and c_job == str(job_name) and \
                            (c_step is None or c_step == index):
                        row = candidate
                        break
                if row is None:
                    findings.append(
                        "%s::%s step %s runs %s but is not reached on push (%s) "
                        "and no reason is recorded"
                        % (wf, job_name, step_label(index, step),
                           ", ".join(scripts), why))
                    continue
                used_rows.add(row[0])
                if not row[4]:
                    findings.append(
                        "ci/gate-job-exceptions.txt:%d excuses %s::%s with an "
                        "empty reason" % (row[0], wf, job_name))

    # A row that matches nothing has rotted against what it names, and a row
    # that cannot fail is how every stale exemption here has started.
    known_jobs = set()
    for path in paths:
        doc = load(path)
        for job_name in (doc.get("jobs") or {}):
            known_jobs.add((os.path.basename(path), str(job_name)))
    judged = {os.path.basename(p) for p in paths}
    for row in exceptions:
        lineno, c_wf, c_job, c_step, _ = row
        if lineno in used_rows:
            continue
        # When named files are judged, a row about a workflow that is not among
        # them says nothing either way; in repository mode every row is judged,
        # which is what makes a row naming a vanished job fail.
        if not repo_mode and c_wf not in judged:
            continue
        if c_job is None:
            findings.append(
                "ci/gate-job-exceptions.txt:%d is not "
                "<workflow>:<job>[:<step>]  <reason>" % lineno)
        elif (c_wf, c_job) not in known_jobs:
            findings.append(
                "ci/gate-job-exceptions.txt:%d names %s::%s, which does not exist"
                % (lineno, c_wf, c_job))
        else:
            findings.append(
                "ci/gate-job-exceptions.txt:%d excuses %s::%s%s, which needs no "
                "excuse -- the row has outlived what it excused"
                % (lineno, c_wf, c_job,
                   "" if c_step is None else " step %d" % c_step))

    if repo_mode:
        want_wf = shape.get("min_workflows")
        want_jobs = shape.get("min_jobs")
        if want_wf is not None and len(paths) < want_wf:
            raise Cannot("found %d workflow(s), ci/workflow-shape.txt declares at "
                         "least %d -- this is a checkout that lost files, not a "
                         "clean result" % (len(paths), want_wf))
        if want_jobs is not None and jobs_total < want_jobs:
            raise Cannot("found %d job(s), ci/workflow-shape.txt declares at least "
                         "%d" % (jobs_total, want_jobs))
        if gate_steps_seen == 0 and tracked("ci/scripts"):
            raise Cannot("no gate step found in a repository that ships gate "
                         "scripts -- the rule measured nothing")

    return findings, gate_steps_seen, jobs_total


def main(argv):
    repo_mode = not argv
    if repo_mode:
        paths = sorted(p for p in tracked(".github/workflows")
                       if p.endswith((".yml", ".yaml")))
        if not paths:
            sys.stderr.write("FATAL: no tracked workflows under "
                             ".github/workflows -- wrong root?\n")
            return 2
    else:
        paths = list(argv)
        for path in paths:
            if not os.path.exists(path):
                sys.stderr.write("FATAL: %s does not exist\n" % path)
                return 2

    exceptions = read_exceptions("ci/gate-job-exceptions.txt")
    shape = read_shape("ci/workflow-shape.txt")

    try:
        findings, gates, jobs = judge(paths, exceptions, shape, repo_mode)
    except Cannot as exc:
        sys.stderr.write("FATAL: %s\n" % exc)
        return 2

    for finding in findings:
        print("FAIL: %s" % finding)
    print("workflow-step-order: %d workflow(s), %d job(s), %d gate step(s), "
          "%d finding(s)%s"
          % (len(paths), jobs, gates, len(findings),
             "" if repo_mode else " [named files only: shape not judged]"))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
