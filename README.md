# docker-anomaly-detection
## 该项目针对容器内的CPU漏洞攻击程序进行静态检测
## 作者
    王玉龙 中国工程物理研究院计算机应用研究所/四川大学网络空间安全研究院
    email：wangyulong@caep.cn
    
  （1）	文件说明：
  ```
        ContainerELFToImage.py：提取指定容器路径下的elf文件，并转换为灰度图
        
        test.py: CNN测试程序
        
        model: 存放训练好的模型
        
        cpu_static_detect.py: 总体测试脚本
```

（2）	测试：

        运行： python cpu_static_detect.py -c 容器id -d 路径，如：
  ![Fig 1](https://github.com/aisthebest/docker-anomaly-detection/blob/main/cpu_detect/test.jpg)

        
        运行完毕后，会生成result文件及detect_result文件：
  
  ![Fig 2](https://github.com/aisthebest/docker-anomaly-detection/blob/main/cpu_detect/elf-gray.jpg)
        
      result 文件为提取的elf生成的灰度图：
 
  ![Fig 3](https://github.com/aisthebest/docker-anomaly-detection/blob/main/cpu_detect/results.jpg)
