#
# We need to use bash for its associative array facility
#
[ "$BASH" ] || exec bash $0
#
# (`bash -p` prevents import of functions from the environment).
#
set -p

declare -A renamed_page

main(){ set -e; cd man/man3; rm -f _*
  count_real_pages
  rename_real_pages
  make_symlinks
}

count_real_pages(){ page_count=0
  for i in $(ls -S)
  do head -n1 $i | grep -E -q '^\.so' && break
    page_count=$(($page_count + 1))
  done
  first_link=$(($page_count + 1))
}

rename_real_pages(){ for i in $(ls -S | head -n$page_count)
  do for j in $(ls -S | tail -n+$first_link)
    do grep -E -q $i$ $j && break
    done
    mv -f $i $j
    renamed_page[$i]=$j
  done
}

make_symlinks(){ for j in $(ls -S | tail -n+$first_link)
  do ln -sf ${renamed_page[$(cat $j | cut -f2 -d/)]} $j
  done
}

main
