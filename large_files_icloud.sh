#!/bin/bash
# Lists your largest personal files (biggest first) and flags which ones
# are good candidates to move to iCloud Drive.
# Usage: ./large_files_icloud.sh [min_size=50M] [max_results=100]
# Output: terminal + ~/Desktop/large_files_report.txt

MIN_SIZE="${1:-50M}"
TOP="${2:-100}"
ROOT="$HOME"
REPORT="$HOME/Desktop/large_files_report.txt"

# stat differs between macOS (BSD) and Linux (GNU)
if stat -f "%z" / >/dev/null 2>&1; then
  STAT=(stat -f "%z	%N")
else
  STAT=(stat -c "%s	%n")
fi

echo "Scanning $ROOT for files larger than $MIN_SIZE (system, hidden, and app files excluded)..." >&2

find "$ROOT" \
  \( -path "$HOME/Library" \
     -o -path "$HOME/.Trash" \
     -o -path "$HOME/Applications" \
     -o -path "$HOME/Public" \
     -o -name ".*" \
     -o -name node_modules \
     -o -name "*.app" \
     -o -name "*.photoslibrary" \
     -o -name "*.musiclibrary" \
     -o -name "*.imovielibrary" \
     -o -name "*.fcpbundle" \
     -o -name "*.lrdata" \
     -o -name "*.xcarchive" \
     -o -name DerivedData \
     -o -name venv -o -name .venv \
  \) -prune -o \
  -type f -size +"$MIN_SIZE" -exec "${STAT[@]}" {} + 2>/dev/null \
  | sort -rn | head -n "$TOP" \
  | awk -F'\t' '
    function human(b) {
      if (b >= 1073741824) return sprintf("%.2f GB", b/1073741824)
      if (b >= 1048576)    return sprintf("%.1f MB", b/1048576)
      return sprintf("%.0f KB", b/1024)
    }
    function ext(p,   n, a) { n = split(p, a, "."); return (n > 1) ? tolower(a[n]) : "" }
    BEGIN {
      printf "%-10s %-8s %s\n", "SIZE", "VERDICT", "PATH"
      printf "%-10s %-8s %s\n", "----", "-------", "----"
      split("mov mp4 m4v avi mkv wmv mpg mpeg heic jpg jpeg png tiff tif raw dng cr2 cr3 nef arw psd ai mp3 wav aiff flac m4a aac pdf doc docx xls xlsx ppt pptx key pages numbers zip rar 7z tar gz tgz dmg iso epub", m, " ")
      for (i in m) move[m[i]] = 1
      split("vmdk vdi qcow2 vhd vhdx sparsebundle sparseimage sqlite sqlite3 db realm log pyc o class a dylib so jar", k, " ")
      for (i in k) keep[k[i]] = 1
    }
    {
      size = $1; path = $2; e = ext(path)
      if (path ~ /\/(\.git|\.npm|\.cache|\.gradle|\.m2|build|dist|target|Pods)\//) v = "KEEP"
      else if (e in keep) v = "KEEP"
      else if (e in move) v = "MOVE"
      else v = "REVIEW"
      printf "%-10s %-8s %s\n", human(size), v, path
      total[v] += size
    }
    END {
      print ""
      printf "Movable to iCloud (MOVE):   %s\n", human(total["MOVE"])
      printf "Needs your call (REVIEW):   %s\n", human(total["REVIEW"])
      printf "Better kept local (KEEP):   %s\n", human(total["KEEP"])
      print ""
      print "MOVE   = media, documents, archives, installers: safe to offload."
      print "REVIEW = unknown type: check before moving."
      print "KEEP   = VM disks, databases, build/dev files: break or slow down when synced."
      print ""
      print "To move: drag files into iCloud Drive in Finder, then right-click > Remove Download"
      print "to free local space."
    }
  ' | tee "$REPORT"

echo "" >&2
echo "Report saved to $REPORT" >&2
