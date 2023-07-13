# Moriartys challenge

## Crack the GLWE

Professor Moriarty has challenged us with a TFHE (Torus Fully Homomorphic encryption) cipher text, which has been encrypted using GLWE (General Learning with Errors) . We need you to decrypt it.

Moriarty's grad students have been kind enough to give us all the parameters you need, which you can find in the main.rs. All except the secret key of course.

Can you decrypt the ciphertext and get your flag?

We have heard that Learning with Errors is a NP hard problem, and before you go here be dragons, we have provided some material below to help you get started.

## example.rs

We have got an example for you in the example.rs file, try to play with it and you will get some intuition as to how it works in a small example. It is a slight generalization of the specific example given in https://www.zama.ai/post/tfhe-deep-dive-part-1 . We recommed going over it in order to understand some background in GLWE and to try the example for getting familiar with the [tfhe-rs](https://github.com/zama-ai/tfhe-rs) library.

The plain text is a polynomial $M$ with $N=4$ coefficients drawn randomly from the sample $-2,-1,0,1$. The polynomial is of degree $N-1$. Note that polynomial multiplications are done in the ring space modulo $X^N+1$. The coefficients are drawn from $\mathcal{R}_p$, with plaintext modulus $p=4$. We have for convenience used zero centered modulus, as in the example.

In GLWE encryption we compute the cipher text

$$C = (A_0,A_1,\ldots A_{k-1},B) \in \mathcal{R}_q^{k+1}$$

where $q=32$ is the cipher text modulus, and

$$B = \sum_{i=0}^{k-1} A_i \cdot S_i + \Delta M+ E $$

The secret vectors $S_i$ consists of random elements in $\{0,1\}$ generated by some seed. The number of secret vectors $k=2$ is chosen to be such that $k < N$ in order to define a LWE problem. The random mask vectors $A_i \in \mathcal{R}_q$ each and are publicly known. The Error vector $E \in \mathcal{R}_q$ has coefficients with absolute value $<\biggl|\frac{\Delta}{2}\biggr|$ where $\Delta = \frac{q}{p}$, note that this condition is essential for proper decryption. Parameters are chosen carefully, else decryption may not work as expected. For eg if you choose the sample for plain text to be uniformly drawn from $-4,-1,0,1,2,3$ you will encounter edge cases when the plain text takes the value $-4$ due to rounding error.

Note: We have added a assert function to detect low hamming weight keys, this might generate panic errors sometimes.

## The flag

* The flag is the decryption of the encrypted ciphertext. It is of the format, the elements in the flag are in i64 format.  

$$[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]$$

* run the check_your_flag(flag) function to check your flag offline.
* Then submit the flag to the website.
* Easter egg hunting alert (NOTHING TO DO WITH FINDING THE FLAG), after you found the flag and claimed your reward. If it strikes your fancy, the flag is not just moonshine.