import pandas as pd
import graphviz

MAX_LINES = 10000

def plot_graph(edges):

    split = []

    if len(edges) > MAX_LINES:
        split = [edges[x:x+MAX_LINES] for x in range(0, len(edges), MAX_LINES)]
    else:
        split.append(edges)

    print('[+] spliting into {} parts'.format(len(split)))

    for i in range(0, len(split)):

        filename = 'plot_' + str(i) + '.gv'
        u = graphviz.Digraph('network', filename=filename,
                        node_attr={'color': 'lightblue2', 'style': 'filled'})
        u.attr(size='6,6')

        for edge in split[i]:
            src = edge[0].replace(":", " ")
            dst = edge[1].replace(":", " ")
            u.edge(src, dst)

        u.view()

"""list of nodes (1d list) and edges (list of tuples (src,dst))
reads the graph's edges from a csv, creates a list of nodes
and a list of edges as tuples
"""
def read_graph():

    nodes = set()
    edges = list()

    df = pd.read_csv('../results/graph.csv')

    for (src,dst) in zip(df['src'], df['dst']):
        
        edges.append((src,dst))
        nodes.add(src)
        nodes.add(dst)

    return (list(nodes), edges)

def main():

    (nodes, edges) = read_graph()
    plot_graph(edges)

if __name__ == '__main__':
    main()