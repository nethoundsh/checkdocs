for nb in $(find . -name "*.ipynb" -not -path "*/.ipynb_checkpoints/*" -not -path "./.*"); do
  echo "=== $nb ==="
  jq -r '[.cells[] | select(.cell_type=="code") | (.outputs // [])[] | select(.output_type == "display_data" or .output_type == "execute_result") | (.data | keys | join(","))] | join("\n")' "$nb"
done
