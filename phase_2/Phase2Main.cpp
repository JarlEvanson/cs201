#include <iostream>
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
	
	cout << *(T2.search("I")) << endl;
	assert(*(T2.search("I")) == 4);
	// Should output 4
	
	cout << T1.rank("I") << endl;
	assert(T1.rank("I") == 9);
	//Should output 9
	
	cout << T1.select(3) << endl;
	assert(T1.select(3) == "C");
	//Should output C 
	
	int result = T2.remove("D");
	cout << result << endl;
	assert(result == 1);
	assert(T2.size() == 11);
	//Should output 1
	
	T2.preorder();
	//Should output "F\n B\n A\n C E\n H K\n G\n I\n L M\n"
	
	T2.inorder();
	//Should output	A B C E F G H I K L M\n
	
	result = T2.remove("J");
	cout << result << endl;
	assert(result == 0);
	assert(T2.size() == 11);
	//Should output 0
	
	cout << T2.rank("G") << endl;
	assert(T2.rank("G") == 6);
	//Should output 6
	
	T2.insert("H",5.1);
	assert(T2.size() == 12);
	T2.insert("H",5.2);
	assert(T2.size() == 13);
	T2.insert("H",5.3);
	assert(T2.size() == 14);

	cout << T2.rank("I") << endl;
	assert(T2.rank("I") == 11);
	//Should output 11

	result = T2.remove("H");
	cout << result << endl;
	assert(T2.size() == 13);
	//Should output 1
	
	float res = *(T2.search("H"));
	cout << res << endl;
	assert(res == (float) 5.1);
	// Should output 5.1
	
	cout << T2.duplicates("H") << endl;
	assert(T2.duplicates("H") == 3);
	//Should output 3
	
	cout << T2.rank("H") << endl;
	assert(T2.rank("H") == 7);
	//Should output 7
	
	cout << T2.size() << endl;
	assert(T2.size() == 13);
	//Should output 13
	
    two4Tree<int,int> X;
	for (int i=1;i<1001000;i++) X.insert(i,i);
	for (int i=1;i<1001000;i++) {
		if(X.rank(i) != i) cout << "Rank error" << endl;
		if(X.select(i) != i) cout << "Select error" << endl;
		if(*(X.search(i)) != i) cout << "Search error" << endl;
	}  
	//Should be no output and should take seconds, not minutes
	return 0;
}
