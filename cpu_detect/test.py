# -*- coding: utf-8 -*-
from __future__ import division
import os   
import numpy as np  
import tensorflow as tf   
from PIL import Image  
import random  
  
# 定义输入节点，对应于图片像素值矩阵集合和图片标签(即所代表的数字)  
x = tf.placeholder(tf.float32, [None, 9216])                        #输入的数据占位符  96*96

#定义一个函数，用于初始化所有的权值 W
def weight_variable(shape):
  initial = tf.truncated_normal(shape, stddev=0.1)
  return tf.Variable(initial)

#定义一个函数，用于初始化所有的偏置项 b
def bias_variable(shape):
  initial = tf.constant(0.1, shape=shape)
  return tf.Variable(initial)
  
#定义一个函数，用于构建卷积层
def conv2d(x, W): #padding为same使输入输出图像大小相同，取值valid则允许输入输出的图像大小不一致
  return tf.nn.conv2d(x, W, strides=[1, 1, 1, 1], padding='VALID') 

#定义一个函数，用于构建池化层
def max_pool(x):
  return tf.nn.max_pool(x, ksize=[1, 2, 2, 1],strides=[1, 2, 2, 1], padding='VALID')

#构建网络
x_image = tf.reshape(x, [-1,96,96,1])         #转换输入数据shape,以便于用于网络中
W_conv1 = weight_variable([5, 5, 1, 8])      #卷积核的个数是8个
b_conv1 = bias_variable([8])       
h_conv1 = tf.nn.relu(conv2d(x_image, W_conv1) + b_conv1)     #第一个卷积层
h_pool1 = max_pool(h_conv1)                                  #第一个池化层

W_conv2 = weight_variable([3, 3, 8, 16])
b_conv2 = bias_variable([16])
h_conv2 = tf.nn.relu(conv2d(h_pool1, W_conv2) + b_conv2)      #第二个卷积层
h_pool2 = max_pool(h_conv2)                                   #第二个池化层

W_conv3 = weight_variable([3, 3, 16, 32])
b_conv3 = bias_variable([32])
h_conv3 = tf.nn.relu(conv2d(h_pool2, W_conv3) + b_conv3)      #第三个卷积层
h_pool3 = max_pool(h_conv3)                                   #第三个池化层

W_conv4 = weight_variable([3, 3, 32, 64])
b_conv4 = bias_variable([64])
h_conv4 = tf.nn.relu(conv2d(h_pool3, W_conv4) + b_conv4)      
h_pool4 = max_pool(h_conv4)                                   

W_conv5 = weight_variable([4, 4, 64, 320])
b_conv5 = bias_variable([320])
h_conv5 = tf.nn.relu(conv2d(h_pool4, W_conv5) + b_conv5) 

W_fc1 = weight_variable([1 * 1 * 320, 512])
b_fc1 = bias_variable([512])
h_conv5_flat = tf.reshape(h_conv5, [-1, 1*1*320])              #reshape成向量
h_fc1 = tf.nn.relu(tf.matmul(h_conv5_flat, W_fc1) + b_fc1)    #第一个全连接层

keep_prob = tf.placeholder("float") 
h_fc1_drop = tf.nn.dropout(h_fc1, keep_prob)                  #dropout层 防止过拟合

W_fc2 = weight_variable([512, 2])
b_fc2 = bias_variable([2])
y_predict=tf.nn.softmax(tf.matmul(h_fc1_drop, W_fc2) + b_fc2)   #softmax层

saver = tf.train.Saver()
#ckpt_dir = "/home/wyl/deeplearning/cmjtest/malware/malware/all-normal"  
ckpt_dir = "./model"  
with tf.Session() as sess:  
    sess.run(tf.global_variables_initializer())  
    test_dir = './result'
    ckpt = tf.train.get_checkpoint_state(ckpt_dir)
    if ckpt and ckpt.model_checkpoint_path:
        saver.restore(sess, ckpt.model_checkpoint_path)
    else:
        print('No checkpoint file found')      
    #saver.restore(sess,ckpt_dir + "/model.ckpt-170") #此处测试不同迭代次数形成的模型需要修改这里的数字 
    result = open("./detect_result",'w+')
    result.truncate()

    index = 0  
    for file in os.listdir(test_dir):
        test_images = np.array([[0]*9216]) 
        filename = test_dir + '/'+ file
        #print(filename)
        img = Image.open(filename)
        img = img.resize((96, 96),resample=Image.LANCZOS)    #设置需要转换的图片大小   
        width = img.size[0]  
        height = img.size[1]  
        for h in range(0, height):  
            for w in range(0, width):   
                if img.getpixel((w, h)) < 190:  
                    test_images[0,w+h*width] = 1 #灰度值转二值
                else:  
                    test_images[0,w+h*width] = 0  
        index += 1  
        prediction = sess.run(y_predict, feed_dict={x:test_images,keep_prob:1.0})
        #print(prediction)
        predict_class = np.argmax(prediction)
        #print(predict_class)
        file = file.split('.')[0]
        split_list = file.split('_')
        split_count = len(split_list)
        container_name = split_list[2]
        test_elf = '/'
        for num in range(4,split_count - 1):
            test_elf = test_elf + split_list[num] + '/'
        test_elf = test_elf + split_list[split_count -1]
        #if predict_class == 1:
            #print('%s is normal' %file)
            #print('program %s in container %s is normal' %(test_elf,container_name))
        if predict_class == 0:
            #print('%s is malicious' %file)
            print >> result,'program %s in container %s is malicious' %(test_elf,container_name)
    result.close()
