all:
	g++ -o example minimal_example.cpp -lpthread -g
	g++ -o workload workload.cpp -fopenmp
