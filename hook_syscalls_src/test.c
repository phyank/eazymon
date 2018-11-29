#include <stdio.h>

long pow(long a,int b){
    if (b<0) return 0;
    else if(b==0){
        return 1;
    }else{
        long c=1;
    for(;b>0;b--)c*=a;
    return c;}
}

void ltostr(const long v,char* buf){

    int index=0;
    long r=v;
    if (v<0) {buf[index]='-';index++;r=-v;};

    int count=0;
    while(r%(pow(10,count))!=r)
        count++;

    long tmp;
    count--;
    for(;;){
        if(count<0)break;

        tmp=r/pow(10,count);
        buf[index]=(char)('0'+tmp);
        index++;

        r=r%pow(10,count);

        count--;
    }

    buf[index]='\0';
    return;

}

void main(){
char buf[1024];
long k= -9223372036854775800l;
ltostr(k,buf);
printf(buf);
}
