package cs.ldfy.util;

import sootup.core.signatures.MethodSignature;
import sootup.core.types.Type;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @Author chenshuo
 * @Date 2024/11/6 7:59
 * @Description: 工具类
 */
public final class ClassUtil {


    public static Method getMethodBySignature(MethodSignature methodSignature) {
        Class<?> aClass;
        Method result = null;
        try {
            aClass = Class.forName(methodSignature.getDeclClassType().toString());
            Method[] methods = aClass.getMethods();
            Optional<Method> any = Arrays.stream(methods)
                    .filter(method -> ClassUtil.compareParameters(method, methodSignature)).findAny();
            if (!any.isPresent()) {return result;}
            result = any.get();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        return result;
    }
    private static boolean compareParameters(Method method, MethodSignature methodSignature) {

        boolean result1 = method.getName().equals(methodSignature.getName()) &&
                method.getReturnType().getName().equals(methodSignature.getType().toString());

        List<String> collect1 = Arrays.stream(method.getParameterTypes()).map(Class::getName).collect(Collectors.toList());
        List<String> collect2 = methodSignature.getParameterTypes().stream().map(Type::toString).collect(Collectors.toList());

        return result1 && collect1.equals(collect2);
    }
}
