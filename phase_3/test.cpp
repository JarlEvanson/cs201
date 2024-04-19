#include "BHeap.cpp"

void test_copy_constructor(BHeap<int> k) {
    assert(k.extractMin() == 20);
}

void floats_test() {
    BHeap<float> floats;

    floats.insert(0.0f);
    floats.insert(2.0f);
    floats.insert(5.0f);
    floats.insert(10.0f);
    floats.insert(-10.0f);
    floats.insert(-20.0f);

    assert(floats.extractMin() == -20.0);
    assert(floats.extractMin() == -10.0);
    assert(floats.extractMin() == 0.0);
    assert(floats.extractMin() == 2.0);
    assert(floats.extractMin() == 5.0);
    assert(floats.extractMin() == 10.0);
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

    floats_test();

    return 0;
}