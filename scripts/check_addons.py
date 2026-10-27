"""Validate the complete client selection using the installed shared Tooling API."""

import argparse
from pathlib import Path

from k8s_stack_tooling.addons import ContractError, validate_selection_images, verify_selection
from k8s_stack_tooling.addons.acquisition import source_checkouts
from k8s_stack_tooling.addons.validation import (
    CLIENT_SOURCE,
    inside,
    render,
    render_stage,
    stage_source,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-dir", default="clusters/prod-eu-1")
    parser.add_argument("--source-cache", type=Path, required=True)
    parser.add_argument("--kube-version", required=True)
    parser.add_argument("--api-version", action="append", default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    base, addons = source_checkouts(root, cluster_dir=args.cluster_dir, cache=args.source_cache)
    verified = verify_selection(
        root, addons, cluster_dir=args.cluster_dir, base=base, installable=True
    )
    roots = {CLIENT_SOURCE: root}
    for source, checkout in [
        (verified.base, base),
        *((a.source, a.checkout) for a in verified.addons),
    ]:
        ref = source.reference
        roots[(ref.kind, ref.namespace, ref.name)] = checkout
    stages = render(inside(root, args.cluster_dir), root=root)
    objects = list(stages)
    for stage in stages:
        if stage.get("kind") != "Kustomization":
            continue
        checkout = roots[stage_source(stage)]
        if checkout == root and inside(root, stage["spec"]["path"]) == inside(
            root, args.cluster_dir
        ):
            continue
        objects.extend(render_stage(stage, checkout))
    maps = {}
    for obj in objects:
        if obj.get("kind") != "ConfigMap":
            continue
        key = (obj["metadata"].get("namespace", ""), obj["metadata"]["name"])
        if key in maps and maps[key] != obj:
            raise ContractError("selected ConfigMap producers disagree")
        maps[key] = obj
    result = validate_selection_images(
        verified,
        client=root,
        base=base,
        configmaps=maps,
        kube_version=args.kube_version,
        api_versions=tuple(args.api_version),
    )
    print(f"Installable source, graph, delivery and image checks passed for {len(result)} add-ons")


if __name__ == "__main__":
    main()
