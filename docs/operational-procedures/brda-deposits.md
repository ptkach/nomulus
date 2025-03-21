# BRDA Deposits

Bulk Registration Data Access (BRDA) is a backup deposit program mandated by
ICANN for most gTLD registrars (ccTLDs are not required to provide BRDA
deposits). Some information related to BRDA can be found at:

https://icannwiki.com/Onboarding_Information_Request#BRDA

BRDA deposits are generated by the
[RdeStagingAction](https://github.com/google/nomulus/blob/master/java/google/registry/rde/RdeStagingAction.java)
job. This is the same job that generates RDE deposits. Its Javadoc goes into
great detail about how it's implemented.

The [RDE task](./rde-deposits.md) performs BRDA processing at 00:00:00 UTC every
Tuesday. RDE runs every day, but only performs the following BRDA steps on
Tuesday (configurable via the `@Config("brdaDayOfWeek")` parameter):

*   Check the BRDA `Cursor`
*   Create a staging file named:
    *   `gs://{PROJECT-ID}-rde/TLD_YYYY-MM-DD_thin_S1_R0.xml.ghostryde`
*   Enqueue a BrdaCopyTask and roll forward the cursor

The BRDA copy task reads the previous file and creates two files:

```
    gs://{PROJECT-ID}-icann-brda/TLD_YYYY-MM-DD_thin_S1_R0.ryde
    gs://{PROJECT-ID}-icann-brda/TLD_YYYY-MM-DD_thin_S1_R0.sig
```

If you see an `xml.ghostryde` file but not the others, an error has occurred
during the process. If you see the files in the
{PROJECT-ID}-icann-brda bucket as well, the process has completed successfully.

Once the files have been created, they must be stored on an sFTP server from
which ICANN can pull the files. The Nomulus project does not provide this last
step; you will need to set up an sFTP server yourself, and copy the files from
Google Cloud Storage to the server.

The cursor can be checked using the `nomulus pending_escrow` command.

## Generating BRDA deposits manually

*   Get a list of "REAL" (as opposed to TEST) TLDs. Doublecheck that the command
    output doesn't contain any TLDs for tests.

```shell
$ registry-tool -e production list_tlds --fields=tldStr,tldType | grep REAL | awk '{print $1}' > realtlds.txt`
```

*   Generate .ryde and .sig files of TLDs specified for given date(s) in the
    current directory.

```shell
$ mkdir /tmp/brda.$$; for date in 2015-02-26 2015-03-05; \
    do for tld in $(cat realtlds.txt); \
    do nomulus -e production create_brda_deposit --tld=${tld} --watermark=${date}T00:00:00Z --outdir=/tmp/brda.$$ & sleep 30; \
    done; \
    done
```

*   Store the generated files to the GCS bucket.

```shell
$ gcloud storage cp /tmp/brda.$$/*.{ryde,sig} gs://{PROJECT-ID}-icann-brda/`
```

*   Mirror the files in the GCS bucket to the sFTP server.
