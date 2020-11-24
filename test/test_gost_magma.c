#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <time.h>

#define SOL_ALG         279
#define BUFF_LENGTH     512

char curr_alg[256];

static uint8_t key[32] = {
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

static uint8_t test_pt[48] = {
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
  0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
};

static uint8_t test_iv[16] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

double time_int_nano (struct timespec *start, struct timespec *end) {
  return (double)(end->tv_sec - start->tv_sec) * 1.0e9 +
    (double)(end->tv_nsec - start->tv_nsec);
}

int print (const char *alg,double interval,uint32_t act) {
  printf ("test: %s :%s passed, elapsed time:%9.2f%% nanosec\n",
    alg, (act == ALG_OP_ENCRYPT) ? "encrypt" : "decrypt", interval);
}

static int crypt_operation(
  int fd, uint8_t *out, uint8_t *in, unsigned int nbytes,
  uint8_t *iv, unsigned int ivlen, uint32_t action)
{
  struct timespec start, end; 
  struct msghdr mh = {};
  struct cmsghdr *cmsg;

  struct iovec iov;
  struct af_alg_iv *aiv;
  uint8_t msgbuf[BUFF_LENGTH] = {};

  mh.msg_control = msgbuf;
  mh.msg_controllen = CMSG_SPACE(4);
  if (ivlen) {
    mh.msg_controllen += CMSG_SPACE(ivlen + 4);
  }
  cmsg = CMSG_FIRSTHDR(&mh);
  cmsg->cmsg_level = SOL_ALG;
  cmsg->cmsg_type = ALG_SET_OP;
  cmsg->cmsg_len = CMSG_LEN(4);
  *(uint32_t *) CMSG_DATA(cmsg) = action;

  if (ivlen) {
    cmsg = CMSG_NXTHDR(&mh, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(ivlen + 4);
    aiv = (void *) CMSG_DATA(cmsg);
    aiv->ivlen = ivlen;
    memcpy(aiv->iv, test_iv, ivlen);
  }
  iov.iov_base = in;
  iov.iov_len = nbytes;
  mh.msg_iov = &iov;
  mh.msg_iovlen = 1;

  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

  if (sendmsg(fd, &mh, 0) == -1)
    return errno;
  if (read(fd, out, nbytes) == -1)
    return errno;

  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

  double interval = time_int_nano(&start, &end);
  print(curr_alg, interval, action);

  return 0;
}

static
int
_check(
  int sd, uint8_t *out, uint8_t *in,
  uint8_t *expected, unsigned int nbytes,
  uint8_t *iv, unsigned int ivlen, uint32_t action)
{
  int i;
  int ret = -1;
  if ((ret = crypt_operation(
    sd, out, in, nbytes, iv, ivlen, action)) != 0) {
    printf ("%s  ret == %d\n",__func__,ret);
    return ret;
  }
  for (i = 0; i < nbytes; i++) {
    if (out[i] != expected[i])
      return -2;
  }

  return 0;
}

static
int
test(
  const char *algname,
  uint8_t *expected,
  uint8_t *iv,
  unsigned int ivlen)
{
  struct sockaddr_alg alg = {
    .salg_family = AF_ALG,
    .salg_type   = "skcipher",
    .salg_name   = "",
  };
  int ret = -1;
  int fd_base[2] = { -1, -1 };
  uint8_t encbuf[BUFF_LENGTH] = {};
  uint8_t decbuf[BUFF_LENGTH] = {};

  strcpy(alg.salg_name, algname);
  fprintf(stdout, "testing %s...\n", algname);
  fflush(stdout);

  strcpy (curr_alg, alg.salg_name);

  fd_base[0] = socket(AF_ALG, SOCK_SEQPACKET, 0);
  if (fd_base[0] <= 0){
    printf ("create socket failed \n");
    goto out;
  }

  ret = bind(fd_base[0], (struct sockaddr *)&alg, sizeof(alg));
  if (ret != 0)
    goto close_fd_base0;

  //set key
  setsockopt(fd_base[0], SOL_ALG, ALG_SET_KEY, key, sizeof(key));
  if ((fd_base[1] = accept(fd_base[0], NULL, 0)) == -1) {
    printf ("accept failed\n");
    goto close_fd_base0;
  }

  //test encryption
  ret = _check(fd_base[1], encbuf, test_pt, expected, sizeof(test_pt),
    iv, ivlen, ALG_OP_ENCRYPT);
  if (ret != 0)
    goto close_fd_base1;

  //test decryption
  ret = _check(fd_base[1], decbuf, encbuf, test_pt,
    sizeof(test_pt), iv, ivlen, ALG_OP_DECRYPT);
  if (ret != 0)
    goto close_fd_base1;

close_fd_base1:
  close(fd_base[1]);
close_fd_base0:
  close(fd_base[0]);
out:
  fprintf(stdout,
    (ret == 0) ? "ok\n" 
               : "\x1b[31mfailed\x1b[0m\n");
  return ret;
}

int
main (int argc, char *argv[])
{
  printf ("\n");
  int ret, r = 0;
  uint8_t magma_ecb_seq[48] = {
    0xa7,0x74,0xd4,0x98,0x4a,0x0e,0x52,0xd2,
    0xcb,0xe0,0x25,0x52,0x2c,0xf7,0x2e,0x0b,
    0xa7,0x74,0xd4,0x98,0x4a,0x0e,0x52,0xd2,
    0xcb,0xe0,0x25,0x52,0x2c,0xf7,0x2e,0x0b,
    0xa7,0x74,0xd4,0x98,0x4a,0x0e,0x52,0xd2,
    0xcb,0xe0,0x25,0x52,0x2c,0xf7,0x2e,0x0b
  };
  uint8_t aes_ecb_seq[48] = {
    0x15,0x0e,0x40,0xcf,0x44,0xf4,0xfb,0x2b,
    0x74,0xfd,0x6d,0xab,0xbe,0x54,0x48,0xd3,
    0x15,0x0e,0x40,0xcf,0x44,0xf4,0xfb,0x2b,
    0x74,0xfd,0x6d,0xab,0xbe,0x54,0x48,0xd3,
    0x15,0x0e,0x40,0xcf,0x44,0xf4,0xfb,0x2b,
    0x74,0xfd,0x6d,0xab,0xbe,0x54,0x48,0xd3
  };
  uint8_t magma_cbc_seq[48] = {
    0xa7,0x74,0xd4,0x98,0x4a,0x0e,0x52,0xd2,
    0xe6,0x0a,0x66,0x01,0xb6,0xa1,0x01,0xf3,
    0x0e,0xa0,0x9c,0xd2,0x49,0xa1,0x8e,0xdc,
    0x68,0x0f,0x90,0xe0,0x0c,0x56,0x65,0xbc,
    0xf2,0x1f,0x23,0xa8,0xff,0xbf,0xbe,0xaf,
    0x80,0x65,0x5b,0x34,0x72,0x86,0xa9,0x5a
  };
  uint8_t aes_cbc_seq[48] = {
    0x15,0x0e,0x40,0xcf,0x44,0xf4,0xfb,0x2b, 
    0x74,0xfd,0x6d,0xab,0xbe,0x54,0x48,0xd3, 
    0xbd,0xd2,0x9a,0x61,0x1e,0x07,0x91,0xa7, 
    0xb0,0xd5,0xcd,0x74,0x12,0xbf,0xcc,0x2e,
    0xca,0x83,0x55,0xb1,0x26,0x0c,0x9f,0x97, 
    0xf7,0x8c,0x77,0x46,0x2f,0x38,0x02,0x29
  };
  
  ret = test("ecb(gost_magma)",magma_ecb_seq,NULL,0);
  printf((ret == 0) ? "test \'ecb(gost_magma)\' have passed\n\n" :
    "test \'ecb(gost_magma)\' have failed\n\n");
  if (ret != 0) r = ret;

  ret = test("ecb(aes)",aes_ecb_seq,NULL,0);
  printf((ret == 0) ? "test \'ecb(aes)\' have passed\n\n" :
    "test \'ecb(aes)\' have failed\n\n");
  if (ret != 0) r = ret;

  ret = test("cbc(gost_magma)",magma_cbc_seq,test_iv,8);
  printf((ret == 0) ? "test \'cbc(gost_magma)\' have passed\n\n" :
    "test \'cbc(gost_magma)\' have failed\n\n");
  if (ret != 0) r = ret;

  ret = test("cbc(aes)",aes_cbc_seq,test_iv,16);
  printf((ret == 0) ? "test \'cbc(aes)\' have passed\n\n" :
    "test \'cbc(aes)\' have failed\n\n");
  if (ret != 0) r = ret;


out:
  printf((r == 0) ? "\nall tests have passed" :
    "there are any failures \n"); 

  return ret;
}
