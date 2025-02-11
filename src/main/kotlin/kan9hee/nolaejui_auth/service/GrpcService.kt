package kan9hee.nolaejui_auth.service

import AuthServerGrpcKt
import kan9hee.nolaejui_auth.component.JwtTokenComponent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.devh.boot.grpc.server.service.GrpcService

@GrpcService
class GrpcService(private val jwtTokenComponent: JwtTokenComponent,
                  private val authService: AuthService)
    :AuthServerGrpcKt.AuthServerCoroutineImplBase() {

    override suspend fun getUserName(request: Auth.AccessToken): Auth.GrpcResult {
        try {
            val username = jwtTokenComponent.getUsernameFrom(request.accessToken)

            return withContext(Dispatchers.Default) {
                Auth.GrpcResult.newBuilder()
                    .setIsSuccess(true)
                    .setResultMessage(username)
                    .build()
            }
        } catch (e: RuntimeException) {
            return withContext(Dispatchers.Default) {
                Auth.GrpcResult.newBuilder()
                    .setIsSuccess(false)
                    .setResultMessage(e.message)
                    .build()
            }
        }
    }

    override suspend fun createAdminAccount(request: Auth.AdminAccount): Auth.GrpcResult {
        try {
            authService.signUpAdminAccount(request.adminId,request.adminPassword)

            return withContext(Dispatchers.Default) {
                Auth.GrpcResult.newBuilder()
                    .setIsSuccess(true)
                    .setResultMessage("ID ${request.adminId}와 비밀번호 ${request.adminPassword}에 대한 관리자 계정 생성됨")
                    .build()
            }
        } catch (e: RuntimeException) {
            return withContext(Dispatchers.Default) {
                Auth.GrpcResult.newBuilder()
                    .setIsSuccess(false)
                    .setResultMessage("${e.message}로 인한 관리자 계정 생성 실패")
                    .build()
            }
        }
    }

    override suspend fun deleteUser(request: Auth.UserName): Auth.GrpcResult {
        try {
            authService.signOutByAdmin(request.userName)

            return withContext(Dispatchers.Default) {
                Auth.GrpcResult.newBuilder()
                    .setIsSuccess(true)
                    .setResultMessage("${request.userName} 계정 삭제됨")
                    .build()
            }
        } catch (e: RuntimeException) {
            return withContext(Dispatchers.Default) {
                Auth.GrpcResult.newBuilder()
                    .setIsSuccess(false)
                    .setResultMessage("${e.message}로 인한 계정 삭제 실패")
                    .build()
            }
        }
    }
}