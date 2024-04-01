#include <cstddef>
#include <cassert>
#include <climits>
#include <iostream>

template<typename T>
void swap_ptr(T* a, T* b) {
    T tmp = *a;
    *a = *b;
    *b = tmp;
}

size_t to_size_t(int num) {
    static_assert(sizeof(int) < sizeof(size_t));

    assert(num >= 0);

    return (size_t) num;
}

int to_int(size_t num) {
    assert(num <= (size_t) INT_MAX);

    return (int) num;
}

size_t wrap_underlying(size_t index, size_t buffer_size) {
    assert(index <= buffer_size || index == (0 - 1) && buffer_size != 0);

    if(index == buffer_size) {
        return 0;
    } else if(index == (size_t) ((size_t) 0 - (size_t) 1)) {
        return buffer_size - 1;
    }

    return index;
}

template<typename T>
class CircularDynamicArray {
private:
    T* base;
    size_t buffer_size;
    size_t size;

    size_t start;
    size_t end;

    T* get(size_t index);
    void grow();
    void shrink();
public:
    CircularDynamicArray();
    CircularDynamicArray(size_t size);
    CircularDynamicArray(CircularDynamicArray& other);
    CircularDynamicArray& operator=(CircularDynamicArray& other);
    ~CircularDynamicArray();

    T& operator[](size_t i);

    void addEnd(T element);
    void addFront(T element);

    void delEnd();
    void delFront();

    void clear();

    int length();
};

template<typename T>
CircularDynamicArray<T>::CircularDynamicArray() {
    this->base = NULL;
    this->buffer_size = 0;
    this->size = 0;

    this->start = 0;
    this->end = 0;
}

template<typename T>
CircularDynamicArray<T>::CircularDynamicArray(size_t size) {
    this->base = new T[size];
    this->buffer_size = size;
    this->size = size;

    this->start = 0;
    this->end = 0;
}

template<typename T> 
CircularDynamicArray<T>::CircularDynamicArray(CircularDynamicArray& other) {
    if(other.base == NULL) {
        this->base = NULL;
    } else {
        this->base = new T[other.buffer_size];
    }
    this->buffer_size = other.buffer_size;
    this->size = other.size;

    this->start = 0;
    this->end = other.size % other.buffer_size;

    for(size_t i = 0; i < this->size; i++) {
        this->base[i] = *other.get(i);
    }
}

template<typename T> 
CircularDynamicArray<T>& CircularDynamicArray<T>::operator=(CircularDynamicArray& other) {
    if(this == &other) 
        return *this;

    delete[] this->base; 

    if(other.base == NULL) {
        this->base = NULL;
    } else {
        this->base = new T[other.buffer_size];
    }
    this->buffer_size = other.buffer_size;
    this->size = other.size;

    this->start = 0;
    this->end = other.size % other.buffer_size;

    for(size_t i = 0; i < this->size; i++) {
        this->base[i] = *other.get(i);
    }

    return *this;
}

template<typename T>
CircularDynamicArray<T>::~CircularDynamicArray() {
    delete[] this->base;

    this->base = NULL;
    this->buffer_size = 0;
    this->size = 0;

    this->start = 0;
    this->end = 0;
}

template<typename T>
T& CircularDynamicArray<T>::operator[](size_t i) {
    return *this->get(i);
}

template<typename T>
T* CircularDynamicArray<T>::get(size_t index) {
    assert(index < this->size);

    size_t underlying_index = this->start;
    size_t elements_before_wrap = this->buffer_size - this->start;

    if(index >= elements_before_wrap) {
        index -= elements_before_wrap;
        underlying_index = 0;
    }

    return &this->base[underlying_index + index];
}

template<typename T>
void CircularDynamicArray<T>::grow() {
    size_t new_buffer_size = this->buffer_size * 2;
    assert(this->buffer_size == new_buffer_size / 2);
    
    if(this->buffer_size == 0) {
        new_buffer_size = 2;
    } 
        
    T* new_ptr = new T[new_buffer_size];
    size_t old_index = this->start;

    for(size_t i = 0; i < this->size; i++) {
        new_ptr[i] = this->base[old_index];
        
        old_index += 1;
        if(old_index == this->buffer_size) {
            old_index = 0;
        }
    }

    delete[] this->base;
    this->base = new_ptr;
    this->buffer_size = new_buffer_size;
    this->start = 0;
    this->end = this->size;
}

template<typename T>
void CircularDynamicArray<T>::addFront(T element) {
    if(this->size == this->buffer_size) {
        this->grow();
    }

    size_t new_start = wrap_underlying(this->start - 1, this->buffer_size);
    
    this->start = new_start;
    this->base[this->start] = element;

    this->size += 1;
}

template<typename T>
void CircularDynamicArray<T>::addEnd(T element) {
    if(this->size == this->buffer_size) {
        this->grow();
    }

    size_t new_end = wrap_underlying(this->end + 1, this->buffer_size);
    
    this->base[this->end] = element;

    this->end = new_end;
    this->size += 1;
}

template<typename T>
void CircularDynamicArray<T>::shrink() {
    size_t new_buffer_size = this->buffer_size / 2;

    T* new_ptr = new T[new_buffer_size];
    size_t old_index = this->start;

    for(size_t i = 0; i < this->size; i++) {
        new_ptr[i] = this->base[old_index];

        old_index += 1;
        if(old_index == this->buffer_size) {
            old_index = 0;
        }
    }

    delete[] this->base;
    this->base = new_ptr;
    this->buffer_size = new_buffer_size;
    this->start = 0;
    this->end = this->size;
}

template<typename T>
void CircularDynamicArray<T>::delFront() {
    if(this->size == 0) {
        return;
    }

    size_t new_front = wrap_underlying(this->start + 1, this->buffer_size);

    this->start = new_front;
    this->size -= 1;

    if(this->size * 4 <= this->buffer_size && this->size * 4 >= this->size) {
        this->shrink();
    }
}

template<typename T>
void CircularDynamicArray<T>::delEnd() {
    if(this->size == 0) {
        return;
    }

    size_t new_end = wrap_underlying(this->end - 1, this->buffer_size);

    this->end = new_end;
    this->size -= 1;

    if(this->size * 4 <= this->buffer_size && this->size * 4 >= this->size) {
        this->shrink();
    }
}

template<typename T>
void CircularDynamicArray<T>::clear() {
    delete[] this->base;
    this->base = NULL;
    this->buffer_size = 0;
    this->size = 0;

    this->start = 0;
    this->end = 0;
}

template<typename T>
int CircularDynamicArray<T>::length() {
    return this->size;
}

#define ENCODE_CONTROL(element_count, internal) ((((unsigned char) (internal)) << 2) | (((element_count) - 1) & 0x3))
#define IS_INTERNAL(node) (((node)->control & 0x4) == 0x4)
#define EXTRACT_CHILD_COUNT(node) (((node)->control & 0x3) + 2)
#define EXTRACT_ELEMENT_COUNT(node) (((node)->control & 0x3) + 1)

template<typename Key, typename Value>
struct FindResult;

template<typename Key, typename Value>
class TwoFourNode {
private:
    CircularDynamicArray<Value> values[3];
    Key keys[3];
    TwoFourNode<Key, Value>* children[4];
    TwoFourNode* parent;
    size_t amount;
    unsigned char control;

    FindResult<Key, Value> find(Key key);
    TwoFourNode(Key key, CircularDynamicArray<Value> values);
    TwoFourNode* adjust_remove(size_t parent_child_index);
    Key* validate_ordering_internal(Key* lower); 

    friend bool unit_test();
public:
    TwoFourNode(Key key, Value value);
    TwoFourNode(TwoFourNode& other);
    ~TwoFourNode();

    Value* search(Key key); 
    void insert(Key key, Value value);
    int remove(Key key);
    int rank(Key key);
    Key select(int pos);
    int duplicates(Key key);
    int size();
    void preorder();
    void inorder(bool* first);
    void postorder();

    void validate(TwoFourNode<Key, Value>* parent);
    void validate_parents(TwoFourNode<Key, Value>* parent);
    void validate_amounts();
    void validate_ordering();
};

template<typename Key, typename Value>
struct FindResult {
    TwoFourNode<Key, Value>* node;
    size_t index;
};

template<typename Key, typename Value>
TwoFourNode<Key, Value>::TwoFourNode(Key key, Value value) {
    CircularDynamicArray<Value> values;
    values.addEnd(value);

    this->keys[0] = key;
    this->values[0] = values;

    this->children[0] = NULL;
    this->children[1] = NULL;
    this->children[2] = NULL;
    this->children[3] = NULL;
    this->parent = NULL;
    this->control = ENCODE_CONTROL(1, false);

    this->amount = 1;
}

template<typename Key, typename Value>
TwoFourNode<Key, Value>::TwoFourNode(TwoFourNode& other) {
    this->parent = NULL;

    for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(&other); i++) {
        this->keys[i] = other.keys[i];
        this->values[i] = other.values[i];
    }

    if(IS_INTERNAL(&other)) {
        for(size_t i = 0; i < EXTRACT_CHILD_COUNT(&other); i++) {
            this->children[i] = new TwoFourNode(*other.children[i]);
            this->children[i]->parent = this;
        }
    }

    this->amount = other.amount;
    this->control = other.control;
}

template<typename Key, typename Value>
TwoFourNode<Key, Value>::TwoFourNode(Key key, CircularDynamicArray<Value> values) {
    this->keys[0] = key;
    this->values[0] = values;

    this->children[0] = NULL;
    this->children[1] = NULL;
    this->children[2] = NULL;
    this->children[3] = NULL;
    this->parent = NULL;
    this->control = ENCODE_CONTROL(1, false);

    this->amount = values.length();
}

template<typename Key, typename Value>
TwoFourNode<Key, Value>::~TwoFourNode() {
    if(IS_INTERNAL(this)) {
        for(size_t i = 0; i < EXTRACT_CHILD_COUNT(this); i++) {
            delete this->children[i];
            this->children[i] = NULL;
        }
    }
}

template<typename Key, typename Value>
FindResult<Key, Value> TwoFourNode<Key, Value>::find(Key key) {
    FindResult<Key, Value> result;

    TwoFourNode<Key, Value>* current = this;

    new_node: {
        size_t index = 0;

        size_t element_count = EXTRACT_ELEMENT_COUNT(current);

        if(IS_INTERNAL(current)) {
            for(index = 0; index < element_count; index++) {
                if(key < current->keys[index]) {
                    break;
                } else if(key == current->keys[index]) {
                    result.node = current;
                    result.index = index;
                    return result;
                }
            }

            current = current->children[index];
            goto new_node;
        } else {
            for(index = 0; index < element_count; index++) {
                if(key == current->keys[index]) {
                    result.node = current;
                    result.index = index;
                    return result;
                }
            }

            result.node = NULL;
            result.index = 0;
            return result;
        }
    }
}

template<typename Key, typename Value>
Value* TwoFourNode<Key, Value>::search(Key key) {
    FindResult result = this->find(key);

    if(result.node == NULL) {
        return NULL;
    }

    return &result.node->values[result.index][0];
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::insert(Key key, Value value) {
    TwoFourNode<Key, Value>* current = this;

    new_node: {
        if(EXTRACT_CHILD_COUNT(current) == 4) {
            Key middle_key = current->keys[1];
            CircularDynamicArray<Value> middle_value = current->values[1];

            TwoFourNode* right = new TwoFourNode(current->keys[2], current->values[2]);
            right->children[0] = current->children[2];
            right->children[1] = current->children[3];
            if(IS_INTERNAL(current)) {
                right->amount += right->children[0]->amount;
                right->amount += right->children[1]->amount;
            }
            right->control = ENCODE_CONTROL(1, IS_INTERNAL(current));

            size_t left_amount = current->values[0].length();
            if(IS_INTERNAL(current)) {
                left_amount += current->children[0]->amount;
                left_amount += current->children[1]->amount;
            }

            if(current->parent == NULL) {
                // Root node

                TwoFourNode* left = new TwoFourNode(current->keys[0], current->values[0]);
                left->children[0] = current->children[0];
                left->children[1] = current->children[1];
                left->control = ENCODE_CONTROL(1, IS_INTERNAL(current));
                left->amount = left_amount;

                left->parent = current;
                right->parent = current;

                if(IS_INTERNAL(current)) {
                    left->children[0]->parent = left;
                    left->children[1]->parent = left;

                    right->children[0]->parent = right;
                    right->children[1]->parent = right;
                }
                
                current->children[0] = left;
                current->children[1] = right;

                current->keys[0] = middle_key;
                current->values[0] = middle_value;

                current->control = ENCODE_CONTROL(1, true);
            } else {
                TwoFourNode* parent = current->parent;
                TwoFourNode* left = current;
                left->children[0] = current->children[0];
                left->children[1] = current->children[1];
                left->control = ENCODE_CONTROL(1, IS_INTERNAL(current));
                left->amount = left_amount;

                if(IS_INTERNAL(left)) {
                    left->children[0]->parent = left;
                    left->children[1]->parent = left;

                    right->children[0]->parent = right;
                    right->children[1]->parent = right;
                } 
                
                size_t parent_index;

                for(parent_index = 0; parent_index < EXTRACT_ELEMENT_COUNT(parent); parent_index++) {
                    if(middle_key < parent->keys[parent_index]) {
                        break;
                    }
                }

                parent->control = ENCODE_CONTROL(EXTRACT_ELEMENT_COUNT(parent) + 1, true);

                for(size_t copy_index = EXTRACT_ELEMENT_COUNT(parent) - 1; copy_index > parent_index; copy_index--) {
                    parent->keys[copy_index] = parent->keys[copy_index - 1];
                    parent->values[copy_index] = parent->values[copy_index - 1];
                }
                for(size_t copy_index = EXTRACT_CHILD_COUNT(parent) - 1; copy_index > parent_index; copy_index--) {
                    parent->children[copy_index] = parent->children[copy_index - 1];
                }
                    
                parent->keys[parent_index] = middle_key; 
                parent->values[parent_index] = middle_value; 

                parent->children[parent_index] = left;
                parent->children[parent_index + 1] = right;

                left->parent = parent;
                right->parent = parent;

                current = parent;
            }
        }

        size_t element_count = EXTRACT_ELEMENT_COUNT(current);

        size_t index;
        for(index = 0; index < element_count; index++) {
            if(key < current->keys[index]) {
                break;
            } else if(key == current->keys[index]) {
                current->values[index].addEnd(value);
                goto adjust_amounts;
            }
        }

        if(IS_INTERNAL(current)) {
            current = current->children[index];
            goto new_node;
        } else {
            // Adding new key

            for(size_t copy_index = element_count; copy_index > index; copy_index--) {
                current->keys[copy_index] = current->keys[copy_index - 1];
                current->values[copy_index] = current->values[copy_index - 1];
            }
            CircularDynamicArray<Value> arr;
            arr.addEnd(value);

            current->keys[index] = key;
            current->values[index] = arr;
            current->control = ENCODE_CONTROL(element_count + 1, false);
            
            goto adjust_amounts;
        }
    }

    adjust_amounts:
    while(current != NULL) {
        current->amount++;
        current = current->parent;
    }
    return;
} 

template<typename Key, typename Value>
TwoFourNode<Key, Value>* TwoFourNode<Key, Value>::adjust_remove(size_t parent_child_index) {
    if(!(EXTRACT_ELEMENT_COUNT(this) == 1 && this->parent != NULL)) {
        return this;
    }

    TwoFourNode* parent = this->parent;

    size_t index;

    bool has_left_sibling = parent_child_index > 0;
    bool has_right_sibling = parent_child_index + 1 < EXTRACT_CHILD_COUNT(parent);

    if(has_right_sibling && EXTRACT_CHILD_COUNT(parent->children[parent_child_index + 1]) > 2) {
        // Right sibling.
        TwoFourNode* right = parent->children[parent_child_index + 1];
        size_t right_count = EXTRACT_ELEMENT_COUNT(right);

        this->keys[1] = parent->keys[parent_child_index];
        this->values[1] = parent->values[parent_child_index];
        this->control = ENCODE_CONTROL(2, IS_INTERNAL(this));
        this->amount += this->values[1].length();

        parent->keys[parent_child_index] = right->keys[0];
        parent->values[parent_child_index] = right->values[0];
        right->control = ENCODE_CONTROL(right_count - 1, IS_INTERNAL(right));
        right->amount -= parent->values[parent_child_index].length();

        this->children[2] = right->children[0];
        if(IS_INTERNAL(this)) {
            this->children[2]->parent = this;

            this->amount += this->children[2]->amount;
            right->amount -= this->children[2]->amount;
        }

        for(index = 0; index < right_count - 1; index++) {
            right->keys[index] = right->keys[index + 1];
            right->values[index] = right->values[index + 1];
            right->children[index] = right->children[index + 1];
        }
        right->children[index] = right->children[index + 1];

        return this;
    } else if(has_right_sibling && EXTRACT_CHILD_COUNT(parent) == 2 && EXTRACT_CHILD_COUNT(parent->children[1]) == 2) {
        // Right sibling.
        TwoFourNode* right = parent->children[1];

        parent->keys[1] = parent->keys[0];
        parent->values[1] = parent->values[0];

        parent->keys[0] = this->keys[0];
        parent->values[0] = this->values[0];

        parent->keys[2] = right->keys[0];
        parent->values[2] = right->values[0];

        parent->control = ENCODE_CONTROL(3, IS_INTERNAL(this) | IS_INTERNAL(right));

        parent->children[0] = this->children[0];
        parent->children[1] = this->children[1];
                
        parent->children[2] = right->children[0];
        parent->children[3] = right->children[1];

        if(IS_INTERNAL(parent)) {
            parent->children[0]->parent = parent;
            parent->children[1]->parent = parent;
            parent->children[2]->parent = parent;
            parent->children[3]->parent = parent;
        }
                
        // Prepare nodes for deletion.
        this->control = ENCODE_CONTROL(2, false);
        right->control = ENCODE_CONTROL(2, false);

        delete this;
        delete right;

        return parent;
    } else if(has_right_sibling && EXTRACT_CHILD_COUNT(parent->children[parent_child_index + 1]) == 2) {
        // Right sibling
        TwoFourNode* right = parent->children[parent_child_index + 1];

        this->keys[1] = parent->keys[parent_child_index];
        this->values[1] = parent->values[parent_child_index];
        for(size_t index = parent_child_index + 1; index < EXTRACT_ELEMENT_COUNT(parent); index++) {
            parent->keys[index - 1] = parent->keys[index];
            parent->values[index - 1] = parent->values[index];
        }

        for(size_t index = parent_child_index + 2; index < EXTRACT_CHILD_COUNT(parent); index++) {
            parent->children[index - 1] = parent->children[index]; 
        }
        this->parent->control = ENCODE_CONTROL(EXTRACT_ELEMENT_COUNT(parent) - 1, true);

        this->keys[2] = right->keys[0]; 
        this->values[2] = right->values[0];

        this->control = ENCODE_CONTROL(3, IS_INTERNAL(this) | IS_INTERNAL(right));

        this->children[3] = right->children[1];
        this->children[2] = right->children[0];

        this->amount = this->values[0].length() + this->values[1].length() + this->values[2].length();

        if(IS_INTERNAL(this)) {
            this->children[0]->parent = this;
            this->amount += this->children[0]->amount;

            this->children[1]->parent = this;
            this->amount += this->children[1]->amount;

            this->children[2]->parent = this;
            this->amount += this->children[2]->amount;

            this->children[3]->parent = this;
            this->amount += this->children[3]->amount;
        }

        right->control = ENCODE_CONTROL(2, false);

        delete right;

        return this;
    } else if(has_left_sibling && EXTRACT_ELEMENT_COUNT(parent->children[parent_child_index - 1]) > 1) {
        // Left sibling.
        TwoFourNode* left = parent->children[parent_child_index - 1];
        size_t left_count = EXTRACT_ELEMENT_COUNT(left);

        this->keys[1] = this->keys[0];
        this->values[1] = this->values[0];
        this->children[2] = this->children[1];
        this->children[1] = this->children[0];
        
        this->keys[0] = parent->keys[parent_child_index - 1];
        this->values[0] = parent->values[parent_child_index - 1];
        this->control = ENCODE_CONTROL(2, IS_INTERNAL(this));
        this->amount += this->values[0].length();

        parent->keys[parent_child_index - 1] = left->keys[left_count - 1];
        parent->values[parent_child_index - 1] = left->values[left_count - 1];
        left->control = ENCODE_CONTROL(left_count - 1, IS_INTERNAL(left));
        left->amount -= parent->values[parent_child_index - 1].length();

        this->children[0] = left->children[left_count];
        if(IS_INTERNAL(this)) {
            this->children[0]->parent = this;

            this->amount += this->children[0]->amount;
            left->amount -= this->children[0]->amount;
        }
        return this;
    } else if(has_left_sibling && EXTRACT_CHILD_COUNT(parent) == 2 && EXTRACT_CHILD_COUNT(parent->children[0]) == 2) {
        // Left sibling.
        TwoFourNode* left = parent->children[0];

        parent->keys[1] = parent->keys[0];
        parent->values[1] = parent->values[0];

        parent->keys[0] = left->keys[0];
        parent->values[0] = left->values[0];

        parent->keys[2] = this->keys[0];
        parent->values[2] = this->values[0];

        parent->control = ENCODE_CONTROL(3, IS_INTERNAL(left) | IS_INTERNAL(this));
                
        parent->children[0] = left->children[0];
        parent->children[1] = left->children[1];

        parent->children[2] = this->children[0];
        parent->children[3] = this->children[1];

        if(IS_INTERNAL(parent)) {
            parent->children[0]->parent = parent;
            parent->children[1]->parent = parent;
            parent->children[2]->parent = parent;
            parent->children[3]->parent = parent;
        }
                
        // Prepare nodes for deletion.
        this->control = ENCODE_CONTROL(2, false);
        left->control = ENCODE_CONTROL(2, false);

        delete this;
        delete left;

        return parent;
    } else if(has_left_sibling && EXTRACT_CHILD_COUNT(parent->children[parent_child_index - 1]) == 2) {
        // Left sibling
        TwoFourNode* left = parent->children[parent_child_index - 1];

        this->keys[2] = this->keys[0];
        this->values[2] = this->values[0];

        this->keys[1] = parent->keys[parent_child_index - 1];
        this->values[1] = parent->values[parent_child_index - 1];

        for(index = parent_child_index; index < EXTRACT_ELEMENT_COUNT(parent); index++) {
            parent->keys[index - 1] = parent->keys[index];
            parent->values[index - 1] = parent->values[index];
        }

        for(index = parent_child_index + 1; index < EXTRACT_CHILD_COUNT(parent); index++) {
            parent->children[index - 1] = parent->children[index];
        }
        parent->control = ENCODE_CONTROL(EXTRACT_ELEMENT_COUNT(parent) - 1, true);
        parent->children[parent_child_index - 1] = this;

        this->keys[0] = left->keys[0];
        this->values[0] = left->values[0];

        this->control = ENCODE_CONTROL(3, IS_INTERNAL(left) | IS_INTERNAL(this));

        this->children[3] = this->children[1];
        this->children[2] = this->children[0];

        this->children[1] = left->children[1];
        this->children[0] = left->children[0];

        this->amount = this->values[0].length() + this->values[1].length() + this->values[2].length();

        if(IS_INTERNAL(this)) {
            this->children[0]->parent = this;
            this->amount += this->children[0]->amount;

            this->children[1]->parent = this;
            this->amount += this->children[1]->amount;

            this->children[2]->parent = this;
            this->amount += this->children[2]->amount;

            this->children[3]->parent = this;
            this->amount += this->children[3]->amount;
        }

        left->control = ENCODE_CONTROL(2, false);

        delete left;

        return this;
    }

    return NULL;
}

template<typename Key, typename Value>
int TwoFourNode<Key, Value>::remove(Key key) {
    if(this->amount == 1 && this->keys[0] == key) {
        this->values[0].delFront();
        if(this->values[0].length() == 0) {
            return 2;
        }
        return 1;
    }

    TwoFourNode<Key, Value>* current = this;

    while(1) {
        if(EXTRACT_ELEMENT_COUNT(current) == 1 && current->parent != NULL) {
            size_t parent_index;

            for(parent_index = 0; parent_index < EXTRACT_ELEMENT_COUNT(current->parent); parent_index++) {
                if(key < current->parent->keys[parent_index]) {
                    break;
                }
            }

            current = current->adjust_remove(parent_index);
            this->validate(this->parent);
            continue;
        }

        size_t element_count = EXTRACT_ELEMENT_COUNT(current);

        size_t index;

        if(IS_INTERNAL(current)) {
            for(index = 0; index < element_count; index++) {
                if(key < current->keys[index]) {
                    break;
                } else if(key == current->keys[index]) {
                    if(current->values[index].length() == 1) {
                        current = current->children[index];
                        goto internal;
                    }

                    current->values[index].delFront();
                    goto adjust_amount;
                }
            }

            current = current->children[index];
        } else {
            for(index = 0; index < element_count; index++) {
                if(key == current->keys[index])  {
                    current->values[index].delFront();

                    if(current->values[index].length() == 0) {
                        for(; index < element_count - 1; index++) {
                            current->keys[index] = current->keys[index + 1];
                            current->values[index] = current->values[index + 1];
                        }

                        current->control = ENCODE_CONTROL(element_count - 1, false);
                    }

                    goto adjust_amount;
                }
            }

            return 0;
        }
    }

    internal:
    while(1) {
        if(EXTRACT_ELEMENT_COUNT(current) == 1 && current->parent != NULL) {
            size_t parent_index = EXTRACT_CHILD_COUNT(current->parent) - 1;

            for(size_t index = 0; index < EXTRACT_ELEMENT_COUNT(current->parent); index++) {
                if(key == current->parent->keys[index]) {
                    parent_index = index;
                    break;
                }
            }

            current = current->adjust_remove(parent_index);
            this->validate(this->parent);
            continue;
        }

        size_t element_count = EXTRACT_ELEMENT_COUNT(current);

        size_t index = EXTRACT_CHILD_COUNT(current) - 1;

        if(IS_INTERNAL(current)) {
            for(size_t i = 0; i < element_count; i++) {
                if(key == current->keys[i]) {
                    index = i;
                }
            }
            current = current->children[index];
        } else {
            current->control = ENCODE_CONTROL(element_count - 1, false);
            Key swap_key = current->keys[element_count - 1];
            CircularDynamicArray<Value> swap_values = current->values[element_count - 1];

            while(current != NULL) {
                for(size_t index = 0; index < EXTRACT_ELEMENT_COUNT(current); index++) {
                    if(key == current->keys[index]) {
                        current->keys[index] = swap_key;
                        current->values[index] = swap_values;
                        goto next_loop;
                    }
                }

                current->amount -= swap_values.length();
                current = current->parent;
            }

            next_loop:
            while(current != NULL) {
                current->amount--;
                current = current->parent;
            }
            
            this->validate(this->parent);

            return 1;
        }
    }

    adjust_amount: {
        while(current != NULL) {
            current->amount--;
            current = current->parent;
        }

        return 1;
    }
}

template<typename Key, typename Value>
int TwoFourNode<Key, Value>::rank(Key key) {
    FindResult result = this->find(key);

    if(result.node == NULL) {
        return 0;
    }

    TwoFourNode* current = result.node;

    size_t rank = 1;
    while(current != NULL) {
        for(size_t index = 0; index < EXTRACT_ELEMENT_COUNT(current); index++) {
            if(key < current->keys[index]) {
                break;
            }

            rank += ((key != current->keys[index]) * current->values[index].length()) + (IS_INTERNAL(current) ? current->children[index]->amount : 0);
        }
        current = current->parent;
    }

    return rank;
}

template<typename Key, typename Value>
Key TwoFourNode<Key, Value>::select(int pos) {
    assert((size_t) pos <= this->amount);

    TwoFourNode* current = this;

    size_t remaining = (size_t) pos;

    new_node: {
        if(IS_INTERNAL(current)) {
            for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(current); i++) {
                if(current->children[i]->amount < remaining) {
                    remaining -= current->children[i]->amount;
                    if(remaining <= current->values[i].length()) {
                        return current->keys[i];
                    }
                    remaining -= current->values[i].length();
                } else {
                    current = current->children[i];
                    goto new_node;
                }
            }
            current = current->children[EXTRACT_CHILD_COUNT(current) - 1];
            goto new_node;
        } else {
            for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(current); i++) {
                if(remaining <= current->values[i].length()) {
                    return current->keys[i];
                }
                remaining -= current->values[i].length();
            }
            assert(false);
        }
    }
}

template<typename Key, typename Value>
int TwoFourNode<Key, Value>::duplicates(Key key) {
    FindResult result = this->find(key);

    if(result.node == NULL) {
        return 0;
    }

    return result.node->values[result.index].length();
}

template<typename Key, typename Value>
int TwoFourNode<Key, Value>::size() {
    return this->amount;
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::preorder() {
    std::cout << this->keys[0];
    for(size_t i = 1; i < EXTRACT_ELEMENT_COUNT(this); i++) {
        std::cout << ' ' << this->keys[i];
    }
    std::cout << '\n';
    if(IS_INTERNAL(this)) {
        for(size_t i = 0; i < EXTRACT_CHILD_COUNT(this); i++) {
            this->children[i]->preorder();
        }
    }
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::inorder(bool* first) {
    if(IS_INTERNAL(this)) {
        for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(this); i++) {
            this->children[i]->inorder(first);
            std::cout << ' ' << this->keys[i];
        }
        this->children[EXTRACT_CHILD_COUNT(this) - 1]->inorder(first);
    } else if(!*first) {
        for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(this); i++) {
            std::cout << ' ' << this->keys[i];
        }
    } else {
        std::cout << this->keys[0];
        for(size_t i = 1; i < EXTRACT_ELEMENT_COUNT(this); i++) {
            std::cout << ' ' << this->keys[i];
        }
        *first = false;
    }
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::postorder() {
    if(IS_INTERNAL(this)) {
        for(size_t i = 0; i < EXTRACT_CHILD_COUNT(this); i++) {
            this->children[i]->postorder();
        }
    }
    std::cout << this->keys[0];
    for(size_t i = 1; i < EXTRACT_ELEMENT_COUNT(this); i++) {
        std::cout << ' ' << this->keys[i];
    }
    std::cout << '\n';
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::validate(TwoFourNode<Key, Value>* parent) {
    this->validate_amounts();
    this->validate_ordering();
    this->validate_parents(parent);
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::validate_parents(TwoFourNode<Key, Value>* parent) {
    assert(this->parent == parent);

    if(IS_INTERNAL(this)) {
        for(size_t i = 0; i < EXTRACT_CHILD_COUNT(this); i++) {
            this->children[i]->validate_parents(this);
        }
    }
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::validate_amounts() {
    size_t amount = 0;
    for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(this); i++) {
        amount += this->values[i].length();
    }

    if(IS_INTERNAL(this)) {
        for(size_t i = 0; i < EXTRACT_CHILD_COUNT(this); i++) {
            this->children[i]->validate_amounts();
            amount += this->children[i]->amount;
        }
    }
    
    assert(amount == this->amount);
}

template<typename Key, typename Value>
Key* TwoFourNode<Key, Value>::validate_ordering_internal(Key* lower) {
    if(IS_INTERNAL(this)) {
        Key* result;

        for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(this); i++) {
            result = this->children[i]->validate_ordering_internal(lower);
            assert(result != NULL);
            assert(*result < this->keys[i]);
            
            lower = &this->keys[i];
        }

        return this->children[EXTRACT_CHILD_COUNT(this) - 1]->validate_ordering_internal(lower);
    } else {
        for(size_t i = 0; i < EXTRACT_ELEMENT_COUNT(this); i++) {
            assert(lower == NULL || *lower < this->keys[i]);
            lower = &this->keys[i];
        }

        return &this->keys[EXTRACT_ELEMENT_COUNT(this) - 1];
    }
}

template<typename Key, typename Value>
void TwoFourNode<Key, Value>::validate_ordering() {
    assert(this->validate_ordering_internal(NULL) != NULL);
}

template<typename Key, typename Value>
class two4Tree {
private:
    TwoFourNode<Key, Value>* top_node;

    friend bool unit_test();
public:
    two4Tree();
    two4Tree(Key keys[], Value values[], int s);
    two4Tree(two4Tree& other);
    two4Tree& operator=(two4Tree& other);
    ~two4Tree();

    Value* search(Key key); 
    void insert(Key key, Value value);
    int remove(Key key);
    int rank(Key key);
    Key select(int pos);
    int duplicates(Key key);
    int size();
    void preorder();
    void inorder();
    void postorder();

    // Testing infrastructure
    void validate();
};

template<typename Key, typename Value>
two4Tree<Key, Value>::two4Tree() {
    this->top_node = NULL;
}

template<typename Key, typename Value>
two4Tree<Key, Value>::two4Tree(Key keys[], Value values[], int s) {
    this->top_node = NULL;

    for(int i = 0; i < s; i++) {
        this->insert(keys[i], values[i]);
    }
}

template<typename Key, typename Value>
two4Tree<Key, Value>::two4Tree(two4Tree& other) {
    if(other.top_node == NULL) {
        this->top_node = NULL;
        return;
    }

    this->top_node = new TwoFourNode(*other.top_node);
}

template<typename Key, typename Value>
two4Tree<Key, Value>& two4Tree<Key, Value>::operator=(two4Tree& other) {
    if(this == &other) {
        return *this;
    }

    delete this->top_node;

    if(other.top_node == NULL) {
        this->top_node = NULL;
        return *this;
    }

    this->top_node = new TwoFourNode(*other.top_node);
    return *this;
}

template<typename Key, typename Value>
two4Tree<Key, Value>::~two4Tree() {
    if(this->top_node == NULL) {
        return;
    }

    delete this->top_node;
    this->top_node = NULL;
}

template<typename Key, typename Value>
Value* two4Tree<Key, Value>::search(Key key) {
    if(this->top_node == NULL) {
        return NULL;
    } 

    return this->top_node->search(key);
}

template<typename Key, typename Value>
void two4Tree<Key, Value>::insert(Key key, Value value) {
    if(this->top_node == NULL) {
        this->top_node = new TwoFourNode(key, value);
    } else {
        this->top_node->insert(key, value);
    }
}

template<typename Key, typename Value>
int two4Tree<Key, Value>::remove(Key key) {
    if(this->top_node == NULL) {
        return 0;
    }

    int result = this->top_node->remove(key);

    if(result == 2) {
        delete this->top_node;
        this->top_node = NULL;
        result = 1;
    }
    
    return result;
}

template<typename Key, typename Value>
int two4Tree<Key, Value>::rank(Key key) {
    if(this->top_node == NULL) {
        return 0;
    }

    return this->top_node->rank(key);
}

template<typename Key, typename Value>
Key two4Tree<Key, Value>::select(int pos) {
    assert(this->top_node != NULL);

    return this->top_node->select(pos);
}

template<typename Key, typename Value>
int two4Tree<Key, Value>::duplicates(Key key) {
    if(this->top_node == NULL) {
        return 0;
    } 

    return this->top_node->duplicates(key);
}

template<typename Key, typename Value>
int two4Tree<Key, Value>::size() {
    if(this->top_node == NULL) {
        return 0;
    } else {
        return this->top_node->size();
    }
}

template<typename Key, typename Value>
void two4Tree<Key, Value>::preorder() {
    if(this->top_node == NULL) {
        return;
    }

    this->top_node->preorder();
}

template<typename Key, typename Value>
void two4Tree<Key, Value>::inorder() {
    if(this->top_node == NULL) {
        return;
    }

    bool first = true;
    this->top_node->inorder(&first);
    std::cout << '\n';
}

template<typename Key, typename Value>
void two4Tree<Key, Value>::postorder() {
    if(this->top_node == NULL) {
        return;
    }    

    this->top_node->postorder();
}

template<typename Key, typename Value>
void two4Tree<Key, Value>::validate() {
    if(this->top_node == NULL) {
        return;
    }

    this->top_node->validate(NULL);
}

bool unit_test() {
    two4Tree<int, long long> add_delete;

    add_delete.insert(0, 0);
    add_delete.remove(0);

    if(add_delete.top_node == NULL) {
        return false;
    }

    return true;
}
