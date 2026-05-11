for nb in $(find . -name "*.ipynb" -not -path "./.*"); do
  echo "=== $nb ==="
  jq -r '[.cells[] | select(.cell_type=="code") | select(.outputs | length > 0) | (.outputs[0].data | keys | join(","))] | join("\n")' "$nb"
done
