#include "BHeap.cpp"

void test_copy_constructor(BHeap<int> k) {
    assert(k.extractMin() == 20);
}

int main() {
    BHeap<int> heap;

    heap.insert(20);
    heap.insert(30);

    test_copy_constructor(heap);

    assert(heap.extractMin() == 20);

    heap.insert(50);

    BHeap<int> copy_assignment;
    copy_assignment = heap;

    assert(heap.extractMin() == 30);

    return 0;
}