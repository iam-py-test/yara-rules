import os

comp_rule = """
"""

for root,dirs,files in os.walk("rules"):
	for file in files:
		if file.endswith(".yar"):
			print("Adding rule {}".format(file))
			comp_rule += open(os.path.join(root,file)).read()
			comp_rule += "\n\n"
out = open("all.yar",'w')
out.write(comp_rule)
out.close()