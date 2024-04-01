#include <iostream>
#include <cassert>
using namespace std;

#include "two4Tree.cpp"

int main(){
    unit_test();

    const size_t element_count = 500;

    two4Tree<int, long> tree;

    // Forward Insert
    
    for(int i = 0; i < element_count; i++) {
        tree.insert(i, i);

        tree.validate();
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.duplicates(i) == 1);
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.remove(i) == 1);

        tree.validate();
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.remove(i) == 0);

        tree.validate();
    }
    
    for(int i = 0; i < element_count; i++) {
        tree.insert(i, (long) i);

        tree.validate();
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.duplicates(i) == 1);
    }

    for(unsigned int i = element_count - 1; i < element_count; i--) {
        assert(tree.remove((int) i) == 1);

        tree.validate();
    }

    // Backward insert

    for(unsigned int i = element_count - 1; i < element_count; i--) {
        tree.insert((int) i, i);

        tree.validate();
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.duplicates(i) == 1);
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.remove(i) == 1);

        tree.validate();
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.remove(i) == 0);

        tree.validate();
    }
    
    for(unsigned int i = element_count - 1; i < element_count; i--) {
        tree.insert((int) i, i);

        tree.validate();
    }

    for(int i = 0; i < element_count; i++) {
        assert(tree.duplicates(i) == 1);
    }

    for(unsigned int i = element_count - 1; i < element_count; i--) {
        assert(tree.remove((int) i) == 1);

        tree.validate();
    }

    int keys[4] = {0,2,3,4};
    int values[4] = {0,2,3,4};

    two4Tree arr_tree(keys, values, 4);
    two4Tree k(arr_tree);

    assert(arr_tree.remove(0) == 1);
    arr_tree.validate();
    assert(arr_tree.remove(2) == 1);
    arr_tree.validate();
    assert(arr_tree.remove(3) == 1);
    arr_tree.validate();
    assert(arr_tree.remove(4) == 1);
    arr_tree.validate();

    assert(k.remove(0) == 1);
    k.validate();
    assert(k.remove(2) == 1);
    k.validate();
    assert(k.remove(3) == 1);
    k.validate();
    assert(k.remove(4) == 1);
    k.validate();
}