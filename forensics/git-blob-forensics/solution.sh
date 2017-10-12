for i in $(./search.py); do git cat-file blob "$i" 2>/dev/null | grep flag; done
