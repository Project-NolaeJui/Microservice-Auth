package kan9hee.nolaejui_auth.service

import AuthServerGrpcKt
import kan9hee.nolaejui_auth.component.JwtTokenComponent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.lognet.springboot.grpc.GRpcService

@GRpcService
class GrpcService(private val jwtTokenComponent: JwtTokenComponent)
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
}