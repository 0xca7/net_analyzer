import networkx as nx
import matplotlib.pyplot as plt

class Visualizer:

    def __init__(self):
        self.G = nx.Graph()

    def add_nodes(self, nodes):
        for node in nodes:
            self.G.add_node(node)
    
    def add_edges(self, edges):
        for edge in edges:
            self.G.add_edge(edge[0], edge[1])

    def show(self, path):
        nx.draw(self.G, with_labels=True, font_weight='bold')
        filename = path + '/' + 'graph.png'
        plt.savefig(filename)
