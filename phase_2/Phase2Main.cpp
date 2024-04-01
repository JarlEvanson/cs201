#include <iostream>
#include <cassert>
using namespace std;
#include "two4Tree.cpp"

int main(){
	string K[12] = {"A","B","C","D","E","F","G","H","I","K","L","M"};
	float V[12] = {12,11,10,9,8,7,6,5,4,3,2,1};
	
	two4Tree<string,float> T1(K,V,12), T2;
	
	for(int i=0; i<12; i++) T2.insert(K[i],V[i]);
	// T1 and T2 should be the same trees
	
	T1.preorder();
	//Should output "D\n B\n A\n C\n F H K\n E\n G\n I\n L M\n"
	
	T2.preorder();
	//Should output "D\n B\n A\n C\n F H K\n E\n G\n I\n L M\n"
	
	T2.inorder();
	//Should output	A B C D E F G H I K L M\n	
	
	float* search_result = T2.search("I");
	cout << *search_result << endl;
	assert(*search_result == (float) 4);
	// Should output 4
	
	int rank_result = T1.rank("I");
	cout << rank_result << endl;
	assert(rank_result == 9);
	//Should output 9
	
	std::string select_result = T1.select(3);
	cout << select_result << endl;
	assert(select_result == "C");
	//Should output C 
	
	int remove_result = T2.remove("D"); 
	cout << remove_result << endl;
	assert(remove_result == 1);
	//Should output 1
	
	T2.preorder();
	//Should output "F\n B\n A\n C E\n H K\n G\n I\n L M\n"
	
	T2.inorder();
	//Should output	A B C E F G H I K L M\n
	
	remove_result = T2.remove("J"); 
	cout << remove_result << endl;
	assert(remove_result == 0);
	//Should output 0
	
	T2.preorder();
	//Should output "F\n B\n A\n C E\n H L\n G\n I K\n M\n"    remove("J") modifies the tree
	
	rank_result = T2.rank("G"); 
	cout << rank_result << endl;
	assert(rank_result == 6);
	//Should output 6
	
	T2.insert("H",5.1);
	T2.insert("H",5.2);
	T2.insert("H",5.3);

	rank_result = T2.rank("I"); 
	cout << rank_result << endl;
	//Should output 11

	remove_result = T2.remove("H"); 
	cout << remove_result << endl;
	assert(remove_result == 1);
	//Should output 1
	
	search_result = T2.search("H"); 
	cout << *search_result << endl;
	assert(*search_result == (float) 5.1);
	// Should output 5.1
	
	int duplicates_result = T2.duplicates("H"); 
	cout << duplicates_result << endl;
	assert(duplicates_result == 3);
	//Should output 3
	
	T2.inorder();
	//Should output	A B C E F G H H H I K L M\n

	T2.preorder();
	//Should output "F\n B\n A\n C E\n H L\n G\n I K\n M\n"  

	rank_result = T2.rank("H"); 
	cout << rank_result << endl;
	assert(rank_result == 7);
	//Should output 7
	
	int size_result = T2.size(); 
	cout << size_result << endl;
	assert(size_result == 13);
	//Should output 13
	
    two4Tree<int,int> X;
	for (int i=1;i<1001000;i++) X.insert(i,i);
	for (int i=1;i<1001000;i++) {
		if(X.rank(i) != i) { cout << "Rank error" << endl; assert(X.rank(i) == i); }
		if(X.select(i) != i) { cout << "Select error" << endl; assert(X.select(i) == i); }
		if(*(X.search(i)) != i) { cout << "Search error" << endl; assert(*(X.search(i)) == i); }
	}  
	//Should be no output and should take seconds, not minutes
	return 0;
}
