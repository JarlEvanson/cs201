#include "BHeap.cpp"

int main() {
    BHeap<int> heap;

    heap.insert(2);
    heap.insert(5);
    heap.consolidate();

    heap.insert(1);
    heap.insert(10);


    heap.consolidate();
    heap.printRootList();

    heap.extractMin();
    heap.printRootList();

    return 0;
}