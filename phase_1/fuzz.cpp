#include <random>

#include <iostream>
#include <cassert>
#include <climits>
using namespace std;
#include "CircularDynamicArray.cpp"

void test_pop_push() {
	CircularDynamicArray<float> C(10);

	for (int i=0; i< C.length();i++) C[i] = i;
	for (int i=0; i< C.length();i++) {
		float test[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		assert(C[i] == test[i]);
	}
	C.delFront();
	for (int i=0; i< C.length();i++) {
		float test[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
		assert(C[i] == test[i]);
	}
	C.delEnd();
	for (int i=0; i< C.length();i++) {
		float test[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
		assert(C[i] == test[i]);
	}
	C.addEnd(100.0);
	for (int i=0; i< C.length();i++) {
		float test[] = { 1, 2, 3, 4, 5, 6, 7, 8, 100.0 };
		assert(C[i] == test[i]);
	}
	C.delFront();
	for (int i=0; i< C.length();i++) {
		float test[] = { 2, 3, 4, 5, 6, 7, 8, 100.0 };
		assert(C[i] == test[i]);
	}
	C.addEnd(200.0);
	for (int i=0; i< C.length();i++) {
		float test[] = { 2, 3, 4, 5, 6, 7, 8, 100.0, 200.0 };
		assert(C[i] == test[i]);
	}
	C.addEnd(300.0);
	for (int i=0; i< C.length();i++) {
		float test[] = { 2, 3, 4, 5, 6, 7, 8, 100.0, 200.0, 300.0 };
		assert(C[i] == test[i]);
	}
	C.addEnd(400.0);
	for (int i=0; i< C.length();i++) {
		float test[] = { 2, 3, 4, 5, 6, 7, 8, 100.0, 200.0, 300.0, 400.0 };
		assert(C[i] == test[i]);
	}
	C.delEnd(); C.delFront();C.delEnd();
	for (int i=0; i< C.length();i++) {
		float test[] = { 3, 4, 5, 6, 7, 8, 100.0, 200.0 };
		assert(C[i] == test[i]);
	}

	for(int i = C.length(); i > 3; i--) {
		C.delEnd();
	}
	assert(C.capacity() == 10);
	C.delEnd();
	assert(C.capacity() == 5);

	size_t iter = C.length() * 2;
	for(int i = C.length() * 2 - 1; i < iter; i--) {
		C.delEnd();
	}
	assert(C.length() == 0);

	return;
}

void test_copy_assignment() {
	CircularDynamicArray<int> A,B;

	B.addEnd(2);

	for(int i=0; i<10;i++) A.addEnd(i);
	B = A;

	A.delFront();
	A.addFront(20);

	assert(A[0] == 20);
	assert(B[0] == 0);

	for(int i = 1; i < 10; i++) {
		assert(A[i] == i);
		assert(B[i] == i);
	}
}

void test_copy_constructor() {
	CircularDynamicArray<int> A;
	for(int i=0; i<10;i++) A.addEnd(i);

	CircularDynamicArray<int> B = A;
	
	A.delFront();
	A.addFront(20);

	assert(A[0] == 20);
	assert(B[0] == 0);
	for(int i = 1; i < 10; i++) {
		assert(A[i] == i);
		assert(B[i] == i);
	}
}

void test_search_select() {
	CircularDynamicArray<int> A;
	for(int i=0; i<20;i++) A.addEnd(i);
	A.addEnd(100); A.addEnd(167);

	assert(A.linearSearch(5) == 5);
	assert(A.binSearch(22) == -1);
	assert(A.binSearch(100) == 20);

	A.addFront(20);

	assert(A.linearSearch(4) == 5);

	A.Sort();

	assert(A.QSelect(1) == 0);
	assert(A.QSelect(3) == 2);
	assert(A.QSelect(20) == 19);
	assert(A.QSelect(21) == 20);
	assert(A.QSelect(22) == 100);
	assert(A.QSelect(23) == 167);
}

void test_sort() {
	CircularDynamicArray<int> A;
	for(size_t i=9; i<10;i--) A.addEnd(i); 
	A.addEnd(15); A.addEnd(19);

	A.Sort();

	int last = 0;
	for(size_t index = 0; index < A.length(); index++) {
		assert(last <= A[index]);
		last = A[index];
	}
}

void test_out_of_bounds() {
	CircularDynamicArray<int> A(0);

	A[0];
}

class DestructorTest {
public:
	~DestructorTest() {
		assert(false);
	}	
};

void test_vector() {
	CircularDynamicArray<vector<int>> A(10);

	A[0].push_back(00);
	A[1].push_back(10);
	A[2].push_back(20);
	A[3].push_back(30);
	A[4].push_back(40);
	A[5].push_back(50);

	{ CircularDynamicArray<vector<int>> B(A); }

	assert(A[0][0] == 00);
	assert(A[1][0] == 10);
	assert(A[2][0] == 20);
	assert(A[3][0] == 30);
	assert(A[4][0] == 40);
	assert(A[5][0] == 50);
}

enum FuzzStatus {
	Success,
	QSelectFail,
	SortFail,
	SearchFail,
};

struct FuzzResult {
	FuzzStatus status;
	size_t fuzz_seed;
	size_t length;
	size_t failure_index;
	size_t failure_data_0;
	size_t failure_data_1;
};

struct FuzzResult fuzz(size_t initial_seed, size_t max_length, size_t iterations) {
	size_t fuzz_seed = initial_seed;

	struct FuzzResult result;

	for(size_t fuzz_index = 0; fuzz_index < iterations; fuzz_index++) {
		std::minstd_rand0 rand_gen(fuzz_seed);

		result.fuzz_seed = fuzz_seed;
		fuzz_seed += 1;

		size_t base_length = rand_gen() % max_length;
		size_t bin = 0;
		size_t lin = 0;
		const size_t q_select_test_count = 100;
		uint32_t q_select_test_value[q_select_test_count];
		size_t q_select_test_nth[q_select_test_count];
		uint32_t last = 0;
		size_t failure_index = 0;

		CircularDynamicArray<uint32_t> test(base_length);
		result.length = base_length;

		for(size_t index = 0; index < base_length; index++) {
			test[index] = (uint32_t) rand_gen();
		}

		for(size_t index = 0; index < q_select_test_count && test.length() != 0; index++) {
			size_t nth = 1 + rand_gen() % test.length();

			q_select_test_nth[index] = nth;
			q_select_test_value[index] =  test.QSelect(nth);
		}

		test.Sort();

		for(size_t index = 0; index < test.length(); index++) {
			if(last > test[index]) {
				result.status = FuzzStatus::SortFail;
				result.failure_index = index;
				result.failure_data_0 = test[last];
				result.failure_data_1 = test[index];
				return result;
			} 
			last = test[index];
		}

		for(size_t index = 0; index < q_select_test_count && test.length() != 0; index++) {
			if (q_select_test_value[index] != test[q_select_test_nth[index] - 1]) {
				result.status = FuzzStatus::QSelectFail;
				result.failure_index = index;
				result.failure_data_0 = q_select_test_nth[index];
				result.failure_data_1 = q_select_test_value[index];
				return result;
			}
		}

		uint32_t find;
		for(size_t index = 0; index < 8192; index++) {
			find = rand_gen();

			lin = test.linearSearch(find);
			bin = test.binSearch(find);

			if(((bin == -1 && lin != -1) || (bin != -1 && lin == -1)) || (bin != lin && test[bin] != test[bin])) {
				result.status = FuzzStatus::SearchFail;
				result.failure_index = index;
				result.failure_data_0 = lin;
				result.failure_data_1 = bin;
				return result;
			}
		}
	}

	result.status = FuzzStatus::Success;
	result.fuzz_seed = 0;
	result.length = 0;
	result.failure_index = 0;
	result.failure_data_0 = 0;
	result.failure_data_1 = 0;

	return result;
}

void print_failure(struct FuzzResult* failure) {
	switch(failure->status) {
		case FuzzStatus::SearchFail:
			cout << "SearchFail\n";
			cout << "Seed: " << failure->fuzz_seed << '\n';
			cout << "Length: " << failure->length << '\n';
			cout << "Linear Search Index: " << failure->failure_data_0 << '\n';
			cout << "Binary Search Index: " << failure->failure_data_1 << '\n';  
			break;
		case FuzzStatus::QSelectFail:
			cout << "SearchFail\n";
			cout << "Seed: " << failure->fuzz_seed << '\n';
			cout << "Length: " << failure->length << '\n';
			cout << "K argument: " << failure->failure_data_0 << '\n';
			cout << "Kth element value: " << failure->failure_data_1 << '\n';  
			break;
		case FuzzStatus::SortFail:
			cout << "SearchFail\n";
			cout << "Seed: " << failure->fuzz_seed << '\n';
			cout << "Length: " << failure->length << '\n';
			cout << "Prev: " << failure->failure_data_0 << '\n';
			cout << "Current: " << failure->failure_data_1 << '\n';  
			break;
	}
} 

int main(){
	test_pop_push();
	test_copy_assignment();
	test_copy_constructor();
	test_search_select();
	test_sort();
	test_out_of_bounds();
	test_vector();

fuzzing:

	cout << "starting fuzzing" << endl;

	struct FuzzResult result = fuzz(0, 100, 10000);
	if (result.status != FuzzStatus::Success) {
		print_failure(&result);
		return -1;
	} 

	cout << "started large array fuzzing" << endl;

	result = fuzz(0, 1024 * 1024 * 1024 / 2, 10000);
	if (result.status != FuzzStatus::Success) {
		print_failure(&result);
		return -1;
	} 
}

