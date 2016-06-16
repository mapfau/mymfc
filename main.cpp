#include "system.h"
#include "main.h"

#include <EGL/egl.h>
#include <GLES2/gl2.h>

#define EGL_EGLEXT_PROTOTYPES 1
#include <EGL/eglext.h>

#define GL_GLEXT_PROTOTYPES 1
#include <GLES2/gl2ext.h>

#include <drm/drm_fourcc.h>

#ifdef CLASSNAME
#undef CLASSNAME
#endif
#define CLASSNAME "Main"

void Cleanup() {
  if (m_cVideoCodec)
    delete m_cVideoCodec;
  if (m_cHints)
    delete m_cHints;
  if (m_pDvdVideoPicture)
    delete m_pDvdVideoPicture;

  avcodec_close(codecCtx);
  av_free(codecCtx);
  avformat_close_input(&formatCtx);
}

void intHandler(int dummy=0) {
  Cleanup();
  exit(0);
}

/************************** EGL ****************************/

void GL_CheckError()
{
  int error = glGetError();

  if (error != GL_NO_ERROR)
  {
    printf("eglGetError(): %i (0x%.4x)\n", (int)error, (int)error);
    exit(1);
  }
}

const char* vertexSource = "\n \
attribute mediump vec4 Attr_Position;\n \
attribute mediump vec2 Attr_TexCoord0;\n \
\n \
uniform mat4 WorldViewProjection;\n \
\n \
varying mediump vec2 TexCoord0;\n \
\n \
void main()\n \
{\n \
\n \
  gl_Position = Attr_Position * WorldViewProjection;\n \
  TexCoord0 = Attr_TexCoord0;\n \
}\n \
\n \
 ";

const char* fragmentSource = "\n \
uniform lowp sampler2D DiffuseMap;\n \
\n \
varying mediump vec2 TexCoord0;\n \
\n \
void main()\n \
{\n \
  mediump vec4 rgba = texture2D(DiffuseMap, TexCoord0);\n \
\n \
  gl_FragColor = rgba;\n \
}\n \
\n \
";

const float quad[] =
{
  -1,  1, 0,
  -1, -1, 0,
  1, -1, 0,

  1, -1, 0,
  1,  1, 0,
  -1,  1, 0
};

const float quadUV[] =
{
  0, 0,
  0, 1,
  1, 1,

  1, 1,
  1, 0,
  0, 0
};

EGLDisplay display;

void initGL()
{
    EGLint major, minor;

    display = eglGetDisplay(EGL_DEFAULT_DISPLAY);

    if (!eglInitialize(display, &major, &minor)) {
        printf("failed to initialize %d\n",eglGetError());
        exit(1);
    } else
        puts(eglQueryString(display,EGL_EXTENSIONS));

    if (!eglBindAPI(EGL_OPENGL_ES_API)) {
        printf("failed to bind api EGL_OPENGL_ES_API\n");
        exit(1);
    }

  // Shader
  GLuint vertexShader = 0;
  GLuint fragmentShader = 0;

  for (int i = 0; i < 2; ++i)
  {
    GLuint shaderType;
    const char* sourceCode;

    if (i == 0)
    {
      shaderType = GL_VERTEX_SHADER;
      sourceCode = vertexSource;
    }
    else
    {
      shaderType = GL_FRAGMENT_SHADER;
      sourceCode = fragmentSource;
    }

    GLuint openGLShaderID = glCreateShader(shaderType);
    GL_CheckError();

    const char* glSrcCode[1] = { sourceCode };
    const int lengths[1] = { -1 }; // Tell OpenGL the string is NULL terminated

    glShaderSource(openGLShaderID, 1, glSrcCode, lengths);
    GL_CheckError();

    glCompileShader(openGLShaderID);
    GL_CheckError();

    GLint param;

    glGetShaderiv(openGLShaderID, GL_COMPILE_STATUS, &param);
    GL_CheckError();

    if (param == GL_FALSE)
    {
      puts("Shader Compilation Failed.");
      exit(-1);
    }

    if (i == 0)
    {
      vertexShader = openGLShaderID;
    }
    else
    {
      fragmentShader = openGLShaderID;
    }
  }

  // Program
  GLuint openGLProgramID = glCreateProgram();
  GL_CheckError();

  glAttachShader(openGLProgramID, vertexShader);
  GL_CheckError();

  glAttachShader(openGLProgramID, fragmentShader);
  GL_CheckError();


  // Bind
  glEnableVertexAttribArray(0);
  GL_CheckError();

  glBindAttribLocation(openGLProgramID, 0, "Attr_Position");
  GL_CheckError();

  glEnableVertexAttribArray(1);
  GL_CheckError();

  glBindAttribLocation(openGLProgramID, 1, "Attr_TexCoord0");
  GL_CheckError();

  glLinkProgram(openGLProgramID);
  GL_CheckError();

  glUseProgram(openGLProgramID);
  GL_CheckError();

  // Get program uniform(s)
  GLuint wvpUniformLocation = glGetUniformLocation(openGLProgramID, "WorldViewProjection");
  GL_CheckError();

  if (wvpUniformLocation < 0)
  {
    printf("wvpUniformLocation failed");
    exit(-1);
  }

  // Set the matrix
  static float m[16]={1.0,0.0,0.0,0.0, 0.0,1.0,0.0,0.0, 0.0,0.0,1.0, 0.0,0.0,0.0,1.0};
  glUniformMatrix4fv(wvpUniformLocation, 1, GL_FALSE, m);
  GL_CheckError();

  // Setup OpenGL
  //glClearColor(1, 0, 0, 1); // RED for diagnostic use
  glClearColor(0, 0, 0, 0);   // Transparent Black
  GL_CheckError();

  glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
  GL_CheckError();

  glEnable(GL_CULL_FACE);
  GL_CheckError();

  glCullFace(GL_BACK);
  GL_CheckError();

  glFrontFace(GL_CCW);
  GL_CheckError();
}

void EnableTexture(DVDVideoPicture *picture)
{
  static GLuint textures[8]={0,0,0,0,0,0,0,0};

  if(!textures[picture->iIndex])
  {
    EGLint img_attrs[] = {
      EGL_WIDTH, picture->iWidth,
      EGL_HEIGHT, picture->iHeight,
      EGL_LINUX_DRM_FOURCC_EXT, DRM_FORMAT_RGBA8888,
      EGL_DMA_BUF_PLANE0_FD_EXT, (EGLint)picture->data[0],
      EGL_DMA_BUF_PLANE0_OFFSET_EXT, 0,
      EGL_DMA_BUF_PLANE0_PITCH_EXT, picture->iLineSize[0],
      EGL_NONE
    };

    EGLImageKHR image = eglCreateImageKHR(display, EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT, 0, img_attrs);
    GL_CheckError();

    glGenTextures(1, &textures[picture->iIndex]);
    GL_CheckError();

    glActiveTexture(GL_TEXTURE0);
    GL_CheckError();

    glBindTexture(GL_TEXTURE_2D, textures[picture->iIndex]);
    GL_CheckError();

    glTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    GL_CheckError();

    glTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    GL_CheckError();

    glEGLImageTargetTexture2DOES(GL_TEXTURE_2D, image);
    GL_CheckError();
  }
  // Upload texture data
  glActiveTexture(GL_TEXTURE0);
  GL_CheckError();

  glBindTexture(GL_TEXTURE_2D, textures[picture->iIndex]);
  GL_CheckError();

  // Set the quad vertex data
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 3 * 4, quad);
  GL_CheckError();

  glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 2 * 4, quadUV);
  GL_CheckError();


  // Draw
  glDrawArrays(GL_TRIANGLES, 0, 3 * 2);
  GL_CheckError();
}

/************************** EGL ****************************/

int main(int argc, char** argv) {
  m_cVideoCodec = NULL;
  m_cHints = NULL;
  m_pDvdVideoPicture = NULL;
  formatCtx = NULL;
  codecCtx = NULL;
  codecParameters = NULL;
  codec = NULL;
  AVPacket packet;
  int videoStream = -1;
  const char* vidPath;
  timespec startTs, endTs;

  signal(SIGINT, intHandler);

  if (argc > 1)
    vidPath = (char *)argv[1];
  else
    vidPath = (char *)"video";

  av_register_all();

  if (avformat_open_input(&formatCtx, vidPath, NULL, NULL) != 0) {
    CLog::Log(LOGERROR, "%s::%s - avformat_open_input() unable to open: %s", CLASSNAME, __func__, vidPath);
    return false;
  }
  CLog::Log(LOGDEBUG, "%s::%s - video file: %s", CLASSNAME, __func__, vidPath);

  if (avformat_find_stream_info(formatCtx, NULL) < 0) {
    CLog::Log(LOGERROR, "%s::%s - avformat_find_stream_info() failed.", CLASSNAME, __func__);
    return false;
  }

  for (unsigned int i = 0; i < formatCtx->nb_streams; ++i)
    if (formatCtx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
      videoStream = i;
      break;
    }

  if (videoStream == -1) {
    CLog::Log(LOGERROR, "%s::%s - Unable to find video stream in the file.", CLASSNAME, __func__);
    return false;
  }
  CLog::Log(LOGDEBUG, "%s::%s - Video stream in the file is stream number %d", CLASSNAME, __func__, videoStream);

  codecParameters = formatCtx->streams[videoStream]->codecpar;
  codec = avcodec_find_decoder(codecParameters->codec_id);
  codecCtx = avcodec_alloc_context3(codec);
  if (codec == NULL) {
    CLog::Log(LOGERROR, "%s::%s - Unsupported codec.", CLASSNAME, __func__);
    return false;
  }
  if (avcodec_open2(codecCtx, codec, NULL) < 0) {
    CLog::Log(LOGERROR, "%s::%s - Unable to open codec.", CLASSNAME, __func__);
    return false;
  }
  CLog::Log(LOGDEBUG, "%s::%s - AVCodec: %s, id %d", CLASSNAME, __func__, codec->name, codec->id);

  m_cVideoCodec = new CDVDVideoCodecC1();

  m_cHints = new CDVDStreamInfo();
  m_cHints->software = false;
  m_cHints->extradata = codecParameters->extradata;
  m_cHints->extrasize = codecParameters->extradata_size;
  m_cHints->codec     = codecParameters->codec_id;
  m_cHints->codec_tag = codecParameters->codec_tag;
  m_cHints->width     = codecParameters->width;
  m_cHints->height    = codecParameters->height;

  CLog::Log(LOGDEBUG, "%s::%s - Header of size %d", CLASSNAME, __func__, codecCtx->extradata_size);

  CDVDCodecOptions options;

  if (!m_cVideoCodec->Open(*m_cHints, options)) {
    Cleanup();
    return false;
  }


  CLog::Log(LOGNOTICE, "%s::%s - ===START===", CLASSNAME, __func__);

  // MAIN LOOP

  int frameNumber = 0;
  int ret = 0;
  m_pDvdVideoPicture = new DVDVideoPicture();

  clock_gettime(CLOCK_REALTIME, &startTs);

  av_init_packet(&packet);

  while (av_read_frame(formatCtx, &packet) >= 0) {

    if (packet.stream_index != videoStream)
      continue;

    if (ret < 0) {
      CLog::Log(LOGNOTICE, "%s::%s - Parser has extracted all frames", CLASSNAME, __func__);
      break;
    }
    frameNumber++;

    CLog::Log(LOGDEBUG, "%s::%s - Extracted frame number %d of size %d", CLASSNAME, __func__, frameNumber, packet.size);

    ret = m_cVideoCodec->Decode(packet.data, packet.size, packet.pts, packet.dts);
    if (ret & VC_PICTURE)
      m_cVideoCodec->GetPicture(m_pDvdVideoPicture);

    av_packet_unref(&packet);
    usleep(1000*17);
  }

  CLog::Log(LOGNOTICE, "%s::%s - ===STOP===", CLASSNAME, __func__);

  clock_gettime(CLOCK_REALTIME, &endTs);
  double seconds = (double )(endTs.tv_sec - startTs.tv_sec) + (double )(endTs.tv_nsec - startTs.tv_nsec) / 1000000000;
  double fps = (double)frameNumber / seconds;
  CLog::Log(LOGNOTICE, "%s::%s - Runtime %f sec, fps: %f", CLASSNAME, __func__, seconds, fps);

  Cleanup();
  return 0;
}
