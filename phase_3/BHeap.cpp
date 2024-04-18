#include <cstddef>
#include <cassert>
#include <cstdint>

#include <iostream>

template<typename T>
struct BHeapNode {
    T key;
    BHeapNode<T>* left;
    BHeapNode<T>* right;
    BHeapNode<T>* child;
    size_t degree;
};

template<typename T>
class BHeap {
    // Pointer to minimum node.
    BHeapNode<T>* minimum_heap;
    // Number of nodes in the BHeap
    size_t size;

    // Capacity of the consolidate array
    size_t capacity;
    // The consolidate array
    BHeapNode<T>** arr;


    static void freeNode(BHeapNode<T>* node) {
        if(node == NULL) {
            // Don't need to free a NULL child.
            return;
        }

        // Begin deletion at `node`.
        BHeapNode<T>* current = node;

        do {
            // Save the right sibling of `current`.
            BHeapNode<T>* right_sibling = current->right;
            // Recursively free `current`'s child.
            freeNode(current->child);
            // Delete `current`.
            delete current;

            // Move to the saved right sibling of `current`.
            current = right_sibling;
        } while(current != node); // Iterate until we reach the node we started at.
    }

    void consolidate(BHeapNode<T>* start_ptr) {
        if(this->size < 2) {
            // There is nothing to do if we have less than 2 nodes.
            return;
        }

        // Calculate the number of slots we need for the helper array.
        size_t power_of_two = 0;
        { 
            size_t current = this->size; 
            while(current != 0) { 
                current >>= 1; power_of_two += 1; } 
        }

        if(power_of_two > this->capacity) {
            // If we don't currently have enough slots, then allocate more.
            BHeapNode<T>** new_arr = new BHeapNode<T>*[power_of_two];

            // We don't need to copy the elements since every element should be NULL
            // between calls to `consolidate`.
            for(int i = 0; i < power_of_two; i++)
                new_arr[i] = NULL;

            delete[] this->arr;
            this->arr = new_arr;
            this->capacity = power_of_two;
        }

        BHeapNode<T>* current = start_ptr;
        BHeapNode<T>* next = start_ptr->right;

        do {
            if(this->arr[current->degree] == NULL) {
                // If the slot for `current`'s degree is NULL, then store
                // `current` there and move to the next root.
                this->arr[current->degree] = current;
                current = next;
                next = next->right;
                if(current == start_ptr) {
                    break;
                }
            } else {
                // Otherwise, begin creating a tree. 
                BHeapNode<T>* new_child;
                BHeapNode<T>* root;

                // Determine which root has the minimum key, as that becomes the root node
                // of the new tree.
                if(current->key < this->arr[current->degree]->key) {
                    new_child = this->arr[current->degree];
                    root = current;
                } else {
                    new_child = current;
                    root = this->arr[current->degree];
                }
                // Do some bookkeeping.
                this->arr[current->degree] = NULL;
                root->degree += 1;
                
                if(root->child == NULL) {
                    // If the root has not children, then add the child.
                    root->child = new_child;

                    new_child->left = new_child;
                    new_child->right = new_child;

                    current = root;
                    continue;
                }

                // Link the new child in its proper position.
                BHeapNode<T>* rightmost_child = root->child->left;

                rightmost_child->right = new_child;
                
                new_child->right = root->child;
                new_child->left = rightmost_child;

                root->child->left = new_child;

                current = root;
            }
        } while(1);

        BHeapNode<T>* start = NULL;
        BHeapNode<T>* last = NULL;

        int index;
        for(index = 0; index < this->capacity && start == NULL; index++)
            start = this->arr[index];

        this->arr[index - 1] = NULL;
        last = start;
        this->minimum_heap = start;

        for(; index < this->capacity; index++) {
            if(this->arr[index] != NULL) {
                last->right = this->arr[index];
                this->arr[index]->left = last;

                last = this->arr[index];
                this->arr[index] = NULL;
                if(last->key < this->minimum_heap->key) {
                    this->minimum_heap = last;
                }
            }
        }

        start->left = last;
        last->right = start;
    }

    static void printTreeNode(BHeapNode<T>* tree) {
        if(tree == NULL) {
            return;
        }

        BHeapNode<T>* current = tree;
        do {
            std::cout << ' ' << current->key;

            BHeap<T>::printTreeNode(current->child);

            current = current->right;
        } while(current != tree);
    }

    static BHeapNode<T>* copy(BHeapNode<T>* other) {
        if(other == NULL) {
            return NULL;
        }

        BHeapNode<T>* origin = new BHeapNode<T>();

        BHeapNode<T>* other_current = other;
        BHeapNode<T>* this_current = origin;

        while(1) {
            this_current->key = other_current->key;
            this_current->degree = other_current->degree;
            
            this_current->child = BHeap<T>::copy(other_current->child);

            other_current = other_current->right;

            if(other_current == other) {
                break;
            }

            BHeapNode<T>* tmp = new BHeapNode<T>();
            tmp->left = this_current;

            this_current->right = tmp;
            this_current = tmp;
        }

        this_current->right = origin;
        origin->left = this_current;

        return origin;
    }

public:
    BHeap() {
        this->size = 0;
        this->minimum_heap = NULL;
        this->capacity = 0;
        this->arr = NULL;
    }

    BHeap(T keys[], int size) {
        this->size = 0;
        this->minimum_heap = NULL;
        this->capacity = 0;
        this->arr = NULL;

        for(size_t i = 0; i < size; i++) {
            this->insert(keys[i]);
        }

        this->consolidate(this->minimum_heap);
    }

    BHeap(BHeap<T>& other) {
        this->minimum_heap = BHeap<T>::copy(other.minimum_heap);

        this->arr = NULL;
        this->capacity = 0;

        this->size = other.size;
    }

    BHeap<T>& operator=(BHeap<T>& other) {
        if(this == &other) {
            return other;
        }

        this->minimum_heap = BHeap<T>::copy(other.minimum_heap);

        this->arr = NULL;
        this->capacity = 0;

        this->size = other.size;

        return *this;
    }

    ~BHeap() {
        BHeap<T>::freeNode(this->minimum_heap);

        delete[] this->arr;
        this->arr = NULL;
        this->capacity = 0;

        this->minimum_heap = NULL;
        this->size = 0;
    }

    T peekKey() {
        assert(this->minimum_heap != NULL);

        return this->minimum_heap->key;
    }

    T extractMin() {
        assert(this->size > 0);

        this->size -= 1;

        // There is only a single root if the minimum points to itself.
        bool single_root = this->minimum_heap == this->minimum_heap->left;

        BHeapNode<T>* left = this->minimum_heap->left;
        BHeapNode<T>* right = this->minimum_heap->right;
        BHeapNode<T>* child = this->minimum_heap->child;
        T return_value = this->minimum_heap->key;

        delete this->minimum_heap;

        if(single_root) {
            this->minimum_heap = child;
        } else if(child == NULL) {
            left->right = right; 
            right->left = left; 

            this->minimum_heap = right;
        } else {
            left->right = child;
            right->left = child->left;

            child->left->right = right;
            child->left = left;

            this->minimum_heap = child;
        }

        if(this->minimum_heap == NULL) {
            return return_value;
        } 

        this->consolidate(this->minimum_heap);

        BHeapNode<T>* lowest = NULL;

        BHeapNode<T>* current = this->minimum_heap;
        do {
            if(lowest == NULL || current->key < lowest->key) {
                lowest = current;
            }

            current = current->right;
        } while(current != this->minimum_heap);
            
        this->minimum_heap = lowest;

        return return_value;
    }

    void insert(T key) {
        this->size += 1;

        BHeapNode<T>* new_node = new BHeapNode<T>();
        new_node->key = key;
        new_node->child = NULL;
        new_node->degree = 0;

        if(this->minimum_heap == NULL) {
            new_node->left = new_node;
            new_node->right = new_node;
            this->minimum_heap = new_node;
            return;
        }

        this->minimum_heap->left->right = new_node;
        
        new_node->left = this->minimum_heap->left;
        new_node->right = this->minimum_heap;

        this->minimum_heap->left = new_node;

        if(key < this->minimum_heap->key) {
            this->minimum_heap = new_node;
        }
    }

    void merge(BHeap<T> &other) {
        BHeapNode<T>* left_self = this->minimum_heap->left;
        BHeapNode<T>* left_other = other.minimum_heap;

        BHeapNode<T>* right_self = this->minimum_heap;
        BHeapNode<T>* right_other = other.minimum_heap->left;

        left_self->right = left_other;
        left_other->left = left_self;

        right_self->left = right_other;
        right_other->right = right_self;

        if(other.minimum_heap->key < this->minimum_heap->key) {
            this->minimum_heap = other.minimum_heap;
        }

        other.size = 0;
        other.minimum_heap = NULL;
    }

    void printKey() {
        BHeapNode<T>* current = this->minimum_heap;

        while(true) {
            std::cout << 'B' << current->degree << ":\n";
            std::cout << current->key;
            BHeap<T>::printTreeNode(current->child);

            current = current->right;
            if(current == this->minimum_heap) {
                std::cout << '\n';
                break;
            }
            std::cout << "\n\n";
        }
    }

    bool isEmpty() {
        return this->minimum_heap == NULL;
    }

    void printRootList() {
        std::cout << "PRINT KEY START\n";

        this->printKey();

        std::cout << "PRINT KEY END\n";
    }
};