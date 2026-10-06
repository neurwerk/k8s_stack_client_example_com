"""Apply shared defaults to a Flux export without rewriting unrelated YAML."""

import re
import sys

import yaml


SCRATCH_VOLUME = re.compile(
    r"(?m)^(?P<indent> +)- emptyDir:(?: \{\}|\n"
    r"(?P=indent)    medium: Memory\n(?P=indent)    sizeLimit: 256Mi)\n"
    r"(?P=indent)  name: tmp$"
)
LAYOUT_ERROR = "Expected one canonical source-controller /tmp emptyDir in flux-system."


def field(node: yaml.Node, name: str) -> yaml.Node:
    if not isinstance(node, yaml.MappingNode):
        raise ValueError(LAYOUT_ERROR)
    matches = [value for key, value in node.value if key.value == name]
    if len(matches) != 1:
        raise ValueError(LAYOUT_ERROR)
    return matches[0]


def apply_defaults(content: str) -> str:
    targets = [
        node
        for node, document in zip(
            yaml.compose_all(content, Loader=yaml.SafeLoader), yaml.safe_load_all(content)
        )
        if isinstance(document, dict)
        and document.get("apiVersion") == "apps/v1"
        and document.get("kind") == "Deployment"
        and isinstance(document.get("metadata"), dict)
        and document["metadata"].get("name") == "source-controller"
        and document["metadata"].get("namespace") == "flux-system"
    ]
    if len(targets) != 1:
        raise ValueError(LAYOUT_ERROR)
    target = targets[0]
    if any(
        isinstance(token, (yaml.AnchorToken, yaml.AliasToken))
        for token in yaml.scan(content[target.start_mark.index:target.end_mark.index])
    ):
        raise ValueError(LAYOUT_ERROR)
    pod = target
    for name in ("spec", "template", "spec"):
        pod = field(pod, name)
    containers = field(pod, "containers")
    if not isinstance(containers, yaml.SequenceNode) or len(containers.value) != 1:
        raise ValueError(LAYOUT_ERROR)
    manager = containers.value[0]
    if field(manager, "name").value != "manager":
        raise ValueError(LAYOUT_ERROR)
    mounts = field(manager, "volumeMounts")
    if not isinstance(mounts, yaml.SequenceNode):
        raise ValueError(LAYOUT_ERROR)
    scratch_mounts = [
        mount for mount in mounts.value
        if field(mount, "name").value == "tmp"
        or field(mount, "mountPath").value == "/tmp"
    ]
    if (
        len(scratch_mounts) != 1
        or len(scratch_mounts[0].value) != 2
        or field(scratch_mounts[0], "name").value != "tmp"
        or field(scratch_mounts[0], "mountPath").value != "/tmp"
    ):
        raise ValueError(LAYOUT_ERROR)
    volumes = field(pod, "volumes")
    if not isinstance(volumes, yaml.SequenceNode):
        raise ValueError(LAYOUT_ERROR)
    scratch = [volume for volume in volumes.value if field(volume, "name").value == "tmp"]
    if len(scratch) != 1 or len(scratch[0].value) != 2:
        raise ValueError(LAYOUT_ERROR)
    matches = [
        match for match in SCRATCH_VOLUME.finditer(content)
        if match.start() + len(match["indent"]) + 2 == scratch[0].start_mark.index
    ]
    if len(matches) != 1:
        raise ValueError(LAYOUT_ERROR)
    match = matches[0]
    indent = match["indent"]
    replacement = (
        f"{indent}- emptyDir:\n{indent}    medium: Memory\n"
        f"{indent}    sizeLimit: 256Mi\n{indent}  name: tmp"
    )
    return content[:match.start()] + replacement + content[match.end():]


if __name__ == "__main__":
    try:
        sys.stdout.write(apply_defaults(sys.stdin.read()))
    except (ValueError, TypeError, RecursionError, yaml.YAMLError):
        print(LAYOUT_ERROR, file=sys.stderr)
        sys.exit(1)
