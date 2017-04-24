
int main()
{
        setreuid(0666,6660);
        system("/bin/sh");

        return 0;
}

