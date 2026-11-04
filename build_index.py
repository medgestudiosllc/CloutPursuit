import sys
frag=open('game.html').read()
head_end=frag.index('<canvas')
html='<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">\n'+frag[:head_end]+'</head>\n<body>\n'+frag[head_end:]+'\n</body>\n</html>\n'
open('index.html','w').write(html)
print(len(html))
